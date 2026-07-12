# Sentinel Backup

**Verified, encrypted backup for Windows, with a tamper-evident audit trail.**

Most backup scripts copy a file, assume it worked, and delete the original. If the
copy was truncated, landed on a failing sector, or never made it past the USB
bridge's write cache, you don't find out until the day you need the file — and by
then the only good copy is long gone.

Sentinel does not assume. It hashes the source, encrypts it, writes the encrypted
copy, reads the bytes **back off the destination**, decrypts and hashes them again,
and only releases the original if the two hashes match. If they don't match, the
copy is discarded and your source file stays exactly where it is.

That single discipline — *verify before you release* — is the product. Every file is
also encrypted with AES-256-GCM before it leaves this machine, so the destination —
a local drive, an SMB share, an S3 bucket, or an Azure Blob container — never holds
plaintext.

---

## GUI

```powershell
python sentinel_gui.py
```

A PySide6 control panel over the same engine the CLI uses — nothing about the backup
logic changes, it's the same `SentinelBackup` class either way. Four tabs:

- **Dashboard** — live status (destination connectivity, encryption, capacity, files
  banked), and one-click Run (with a dry-run toggle), Verify, and Prune.
- **Restore** — glob pattern, destination folder picker, dry-run toggle.
- **Config** — every `sentinel_config.json` field as a form (source, local/S3/Azure
  destination settings, release/versioning, retention/filters, encryption key
  management, alerts), with Save/Reload. Includes buttons to generate a new AES-256
  key and set it as your user environment variable, or to initialize a `keyfile`/
  `dpapi` key.
- **Scheduling** — install, check, run, or uninstall the Windows Scheduled Task
  (wraps `Install-SentinelTask.ps1`) without leaving the app.

Only one action runs at a time; the rest of the window stays interactive while a
backup, verify, or restore is in progress, with output streaming into the activity
log at the bottom. Use `pythonw sentinel_gui.py` instead of `python` to launch
without a console window trailing it.

---

## Install

```powershell
pip install -r requirements.txt
python sentinel_backup.py init      # writes sentinel_config.json
```

`boto3` and `azure-storage-blob` are only needed if you use the S3 or Azure
destination respectively; `pywin32` is only needed for `key_source: "dpapi"`. See
`requirements.txt` for details.

### Set up encryption

Every backup is encrypted, so pick a key source before your first run. The simplest:

```powershell
python crypto_utils.py --generate-key
```

Copy the printed value into an environment variable:

```powershell
$env:BACKUP_ENCRYPTION_KEY = "<paste the generated key here>"
```

Set it permanently (so scheduled/unattended runs pick it up) with
`[Environment]::SetEnvironmentVariable("BACKUP_ENCRYPTION_KEY", "<key>", "User")`.
See [Encryption Key Management](#encryption-key-management) for the other three
options (passphrase, key file, DPAPI-protected key file).

### Rehearse, then run

```powershell
python sentinel_backup.py status    # confirm it sees your destination
python sentinel_backup.py run --dry-run
```

`--dry-run` shows every file it *would* encrypt, upload, and hash, and touches
nothing. Run it first. Always run it first.

When you're satisfied:

```powershell
python sentinel_backup.py run
.\Install-SentinelTask.ps1 -IntervalHours 6
```

---

## The one local-destination setting that matters

Open `sentinel_config.json` and set your drive's **volume label**:

```json
{
  "destination_type": "local",
  "target_volume_label": "BACKUP_HDD",
  "target_drive_letter": "E:\\"
}
```

Right-click the drive in File Explorer → Rename → give it a name, and put that name
in `target_volume_label`.

Windows reassigns drive letters constantly — plug in a phone, an SD card, or a
second stick and yesterday's `E:` is today's `G:`. A drive-letter-based backup then
"skips" every cycle, cheerfully, forever, and you never notice. Sentinel scans every
mounted volume for the label and finds your disk no matter what letter it landed on.
The drive letter stays in the config only as a fallback. For an SMB share, set
`target_drive_letter` to a UNC path (e.g. `\\server\share\Backups`) and leave
`target_volume_label` blank — Windows treats UNC paths like local paths.

---

## Commands

```powershell
python sentinel_backup.py status                  # destination, capacity, files banked, last run
python sentinel_backup.py run                     # one verified sync cycle, then exit
python sentinel_backup.py run --dry-run           # rehearsal - writes nothing
python sentinel_backup.py watch                   # continuous loop (dev/testing)
python sentinel_backup.py verify                  # re-download, decrypt, re-hash the whole archive
python sentinel_backup.py restore --to "C:\Recovered" --pattern "*.pdf"
python sentinel_backup.py prune                   # age out old versions (local/SMB only)
```

Exit codes are meaningful, so you can wire this into monitoring:
`0` success · `1` verification failure · `2` destination not connected / key error ·
`3` bad source · `4` insufficient space.

---

## `verify` — the command that justifies the price

Run it monthly. It walks the manifest, downloads and decrypts each file from the
destination, and re-hashes the plaintext against the hash recorded when it was
written. Because AES-256-GCM authenticates every chunk on decrypt, a single flipped
bit anywhere in the encrypted object makes decryption fail outright rather than
silently returning corrupted bytes.

```
Verifying 1,284 file(s) against manifest (local)
------------------------------------------------------------------
  [CORRUPT ] Contracts/2025/msa-final.pdf
             expected a948904f2f0f479b8f819769
             actual   e5b4bdff3472e5db4eac57bd
------------------------------------------------------------------
  1283 intact  |  0 missing  |  1 corrupt or modified
  audit log: audit chain intact
```

That output means one of three things happened to that file: the drive is developing
bad sectors, something modified an archived object out from under Sentinel, or
something corrupted it in transit. All three are things you want to learn about in a
monthly check rather than during a recovery.

---

## The audit trail

Every action lands in a local `_sentinel/logs/audit-YYYY-MM.jsonl` as one JSON object
per line: timestamp, host, user, file path, SHA-256, and how the source was disposed
of. For local/SMB destinations this log lives on the destination itself, alongside
the encrypted backup; for S3/Azure it lives in `.sentinel_state/` next to the script
(there's no "drive" for it to travel with in the cloud case — see
[Where state lives](#where-state-lives)).

Each record also carries the hash of the record before it. Edit or delete any
historical line and every hash after it stops validating — `verify` reports exactly
which line broke. You cannot quietly rewrite this log after the fact.

```json
{"ts":"2026-07-12T19:47:20Z","event":"copy_verified","host":"WS-01","user":"elijah",
 "path":"Contracts/msa-final.pdf","sha256":"a948904f...","disposal":"moved to Recycle Bin",
 "prev":"b780e908...","chain":"25f76e10..."}
```

**What this is honestly good for:** producing durable, verifiable evidence that a
given file was backed up, encrypted, at a given time, with a proven-intact copy — and
that the record hasn't been altered since. That's a genuinely useful artifact when
you need to demonstrate that a data-protection or media-integrity control is actually
operating, not just documented.

**What it is not:** a compliance certification. No script makes an organization SOC 2
or NIST compliant — those are organizational programs assessed across people, process,
and technology. Sentinel is a control *implementation* that generates evidence. Claiming
more than that is the kind of thing an auditor notices, and it will cost you more
credibility than it buys.

If you need to map it: this supports the *Protect* and *Recover* functions of NIST CSF
2.0 (specifically PR.DS-1, data-at-rest protection, and PR.DS-11, backups created,
protected, and verified) and produces evidence relevant to Availability and
Processing Integrity criteria. Cite it that way, not as "SOC 2 compliant."

---

## Encryption and destinations

### Security model

- **At rest:** every file is encrypted individually with AES-256-GCM (authenticated —
  corruption or tampering is detected on decrypt) before it is ever written to a
  destination. This applies to every destination type, including a local external
  drive, so the backup drive itself never holds plaintext.
- **In transit:** for S3 and Azure Blob, uploads happen over HTTPS by default via the
  AWS/Azure SDKs; both destination backends explicitly reject non-HTTPS
  endpoints/connection strings. For a local external drive there is no network
  transit. For an SMB share, also enable SMB 3.x encryption on that share
  (`Set-SmbShare -EncryptData $true`) for transport-level protection in addition to
  the file-level encryption already applied.
- **Restoring:** encrypted files are useless without the same encryption key the
  backup was written with. Whichever `key_source` you use, make sure the key (or the
  means to derive/unprotect it) is itself backed up somewhere safe and separate from
  the backup destination — losing the key means losing the backups.

### Destination configuration

Set `destination_type` in `sentinel_config.json` to `"local"` (default, also covers
SMB/UNC), `"s3"`, or `"azure"`.

**S3** (`destination_type: "s3"`)

- `s3_bucket`, `s3_prefix`, `s3_region` — target bucket/prefix/region.
- `s3_endpoint_url` — only for S3-compatible services (Backblaze B2, MinIO); must be
  `https://`.
- AWS credentials come from the standard AWS credential chain (environment
  variables, `~/.aws/credentials`, or an assumed role) — never hardcode keys here.
- Objects are also uploaded with `ServerSideEncryption=AES256`, in addition to the
  client-side AES-256-GCM encryption already applied.
- `prune` is not implemented for S3 — use an S3 Lifecycle rule on the
  `_sentinel/versions/` prefix instead.

**Azure Blob** (`destination_type: "azure"`)

- `azure_container`, `azure_prefix` — target container (created automatically if
  missing) and prefix.
- `azure_connection_string_env` — name of the environment variable holding your
  connection string (default `AZURE_STORAGE_CONNECTION_STRING`). Must use `https`;
  Sentinel rejects `http` connection strings.
- `prune` is not implemented for Azure — use a Blob lifecycle management policy on
  the `_sentinel/versions/` prefix instead.

### Encryption key management

Set `key_source` in `sentinel_config.json` (or the matching env vars). All modes use
AES-256-GCM under the hood — this only controls where the 32-byte key comes from:

| key_source | How it works | Unattended? | Notes |
|---|---|---|---|
| `env` (default) | Reads a base64 key from the env var named by `key_env_var`. | Yes | Generate one with `python crypto_utils.py --generate-key`. |
| `prompt` | Prompts for a passphrase at startup; a key is derived via PBKDF2 (600,000 iterations) using a salt stored in `backup_salt.bin`. | No | Most explicit option; keep `backup_salt.bin` with your backups. |
| `keyfile` | Auto-generates a random key on first run and saves it (base64) to `%USERPROFILE%\.wolfpak_backup_key` (or `key_file` if set). | Yes | Back up this file somewhere separate from the backup destination. |
| `dpapi` | Same as `keyfile`, but the key is encrypted with Windows DPAPI, tied to your Windows account. Requires `pywin32`. | Yes | Can only be unprotected from this Windows account on this machine. Export an offline copy with `python crypto_utils.py --export-key --key-source dpapi`. |

### Where state lives

- **Local/SMB destination:** the manifest and audit log live under `_sentinel/` on
  the destination itself, next to the encrypted files — the archive is
  self-describing and travels with the drive.
- **S3/Azure destination:** there's no physical drive for the manifest/audit log to
  travel with, so they're kept locally in `.sentinel_state/` next to
  `sentinel_backup.py`. Back this folder up if you rely on it (e.g. for `verify` or
  `restore` from another machine).

---

## What it does not do

Stated plainly, because buyers find these out anyway:

- **Not real-time.** It runs on a schedule. A file created and destroyed between
  cycles is never seen.
- **Windows-first.** The volume-label lookup uses a Win32 call. It runs on macOS/Linux
  with the drive-path fallback, but that path is less tested.
- **Cloud pruning isn't automated.** `prune` only manages local/SMB version files —
  for S3/Azure, use the provider's own lifecycle rules (see above).

---

## Safety design

The things that stop this from eating your data:

1. **Verify before release.** Hash match required, after decryption, no exceptions.
2. **Encrypt before it ever leaves this machine.** Plaintext never touches the
   destination, local or cloud.
3. **Staged, atomic-as-possible writes.** Copies land at a `.sentinel-part` staging
   name and are promoted to their final name only after read-back verification
   passes — a real atomic rename on local/SMB, copy-then-delete on S3/Azure (the
   closest either service offers). A power cut or interrupted upload never leaves a
   plausible-looking half file live in your archive.
4. **`os.fsync()` before local read-back.** Without it you'd be re-reading your own
   OS write cache and verifying nothing at all. This is the detail almost every
   homegrown backup script gets wrong.
5. **No `os.remove()` on a source file, anywhere in the codebase.** Recycle Bin or a
   dated quarantine folder. Both are reversible.
6. **Stability check.** A file still being written (a download in progress, a video
   export) is deferred to the next cycle instead of being backed up half-formed.
7. **Free-space preflight (local/SMB).** Aborts before filling the drive, rather than
   dying halfway.
8. **Versioning.** Existing backups are moved aside, never destroyed to make room.

---

## Requirements

- Windows 10/11 (macOS/Linux run in fallback mode for local destinations)
- Python 3.9+
- `send2trash` — optional. Without it, released files go to a quarantine folder
  instead of the Recycle Bin. Nothing is ever hard-deleted either way.
- `cryptography` — required, powers the AES-256-GCM encryption.
- `pywin32` — only required for `key_source: "dpapi"`.
- `boto3` — only required for `destination_type: "s3"`.
- `azure-storage-blob` — only required for `destination_type: "azure"`.
- `PySide6` — only required to run `sentinel_gui.py`; the CLI has no GUI dependency.

## License

See `LICENSE`.
