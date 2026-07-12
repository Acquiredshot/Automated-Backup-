# Auto Backup Script (Windows + External Drive)

A continuous Python sync script that watches your Desktop folder named **External Backup**, encrypts new items with AES-256-GCM, uploads the encrypted copies to your chosen destination (a local/external drive, an SMB network share, AWS S3, or Azure Blob Storage), and then moves successfully processed source items to the Recycle Bin.

This Tool is designed for Intermediate to Advanced users and can be run directly from PowerShell (with or without VS Code).

## What This Script Does

- Detects your Desktop source folder, including OneDrive Desktop redirection.
- Checks that your local/external drive destination is connected (for local/SMB destinations).
- Encrypts every file individually with AES-256-GCM before it ever leaves your machine (**encryption at rest**).
- Uploads to S3 or Azure Blob Storage over HTTPS/TLS (**encryption in transit**) when using those destinations.
- Continuously watches the source folder on a timer.
- Overwrites existing destination items cleanly.
- Moves successfully processed source items to the Recycle Bin.
- Prints clear cycle-by-cycle logs.

## Project Structure

- `backup_to_external_drive.py` - Main backup script.
- `crypto_utils.py` - AES-256-GCM file encryption/decryption and key management.
- `destinations.py` - Destination backends (local/SMB, S3, Azure Blob).
- `restore_backup.py` - CLI to decrypt/restore backed-up files.

## Requirements

- Windows
- Python 3.8+
- A destination: an external drive letter, an SMB share path, an S3 bucket, or an Azure Storage container
- Python packages: see `requirements.txt`

## Security Model

- **At rest:** every file is encrypted individually with AES-256-GCM (authenticated encryption — corruption or tampering is detected on restore) before it is written to the destination. This applies to every destination type, including a local external drive, so the backup drive itself never holds plaintext.
- **In transit:** for the S3 and Azure Blob destinations, uploads happen over HTTPS by default via the AWS/Azure SDKs; both destination backends explicitly reject non-HTTPS endpoints/connection strings. For a local external drive there is no network transit. For an SMB network share, also turn on SMB 3.x encryption on that share (`New-SmbShare ... -EncryptData $true` or `Set-SmbShare -EncryptData $true`) for transport-level protection in addition to the file-level encryption already applied.
- **Restoring:** encrypted files are useless without the same encryption key the backup was written with. Whichever `KEY_SOURCE` you use, make sure the key (or the means to derive/unprotect it) is itself backed up somewhere safe and separate from the backup destination — losing the key means losing the backups.

## Default Paths Used

- **Source folder name:** `External Backup`
- **Destination drive (default):** `E:\`
- **Destination folder name:** `Automated_Backups`
- **Final destination (default):** `E:\Automated_Backups`

## Quick Start

### 1. Clone or download this project

Place the folder anywhere on your computer.

### 2. Create your source folder on Desktop

Create a folder named:

- `External Backup`

Put any files/folders you want to back up into that folder.

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

If `pip` is not recognized:

```powershell
py -m pip install -r requirements.txt
```

`boto3` and `azure-storage-blob` are only needed if you use the S3 or Azure destination respectively; `pywin32` is only needed for `KEY_SOURCE=dpapi`. See `requirements.txt` for details.

### 4. Set up encryption

Pick a `KEY_SOURCE` (see [Encryption Key Management](#encryption-key-management-key_source) below). The simplest to get started with:

```powershell
python crypto_utils.py --generate-key
```

Copy the printed value into an environment variable before running the script:

```powershell
$env:BACKUP_ENCRYPTION_KEY = "<paste the generated key here>"
```

Set this permanently (so scheduled/unattended runs pick it up) with `[Environment]::SetEnvironmentVariable("BACKUP_ENCRYPTION_KEY", "<key>", "User")`.

### 5. Configure and connect your destination

By default the script targets a local external drive at `E:\`. Connect it, or edit the configuration (see [Configuration](#configuration) below) to point at an SMB share, S3 bucket, or Azure container instead.

### 6. Run from PowerShell

From the project folder:

```powershell
Set-Location "C:\path\to\Auto_Backup"
python ".\backup_to_external_drive.py"
```

If `python` is not recognized:

```powershell
Set-Location "C:\path\to\Auto_Backup"
py ".\backup_to_external_drive.py"
```

Run from any folder (full path):

```powershell
python "C:\path\to\Auto_Backup\backup_to_external_drive.py"
```

## Example Output

```text
============================================================
	WOLF-PAK FILE SYSTEM SHIELD - AUTOMATED SYNC
============================================================
Watching folder: C:\Users\YourName\OneDrive\Desktop\External Backup
Backup target:   E:\Automated_Backups
Encryption:      AES-256-GCM at rest (KEY_SOURCE=env)
Checking every 6 hours. Press Ctrl+C to stop.

🚀 [2026-07-09 10:17:46] New items detected! Starting sync...
📦 Destination: E:\Automated_Backups (encrypted at rest, AES-256-GCM)
--------------------------------------------------
✅ Encrypted + uploaded file:   example.zip
🗑️  Moved to Recycle Bin: example.zip
✨ Sync cycle complete. Source folder is clear.
```

Stop the script any time with `Ctrl+C`.

## Configuration

In `backup_to_external_drive.py`, edit these values, or set the matching environment variable:

- `DESTINATION_TYPE` / `BACKUP_DESTINATION_TYPE` env var — `"local"` (default, also covers SMB/UNC), `"s3"`, or `"azure"`.
- `TARGET_DRIVE_LETTER` (example: `"E:\\"`, or a UNC path like `r"\\server\share"` for SMB) — used when `DESTINATION_TYPE="local"`.
- `BACKUP_FOLDER_NAME` (example: `"Automated_Backups"`).
- `CHECK_INTERVAL_HOURS` (example: `6`).
- `KEY_SOURCE` / `KEY_SOURCE` env var — see below.

### S3 destination (`DESTINATION_TYPE="s3"`)

- `BACKUP_S3_BUCKET` env var — target bucket name.
- `AWS_REGION` env var — bucket region.
- `BACKUP_S3_ENDPOINT_URL` env var — only needed for S3-compatible services (e.g. Backblaze B2, MinIO); must be `https://`.
- AWS credentials come from the standard AWS credential chain (environment variables, `~/.aws/credentials`, or an assumed role) — never hardcode keys in the script.
- Objects are also uploaded with `ServerSideEncryption=AES256` by default, in addition to the client-side AES-256-GCM encryption already applied.

### Azure Blob destination (`DESTINATION_TYPE="azure"`)

- `BACKUP_AZURE_CONTAINER` env var — target container name (created automatically if missing).
- `AZURE_STORAGE_CONNECTION_STRING` env var — your Azure Storage connection string. Must use `https`; the script rejects `http` connection strings.

## Encryption Key Management (`KEY_SOURCE`)

Set via the `KEY_SOURCE` environment variable (or edit the constant in `backup_to_external_drive.py`). All modes use AES-256-GCM under the hood — this only controls where the 32-byte key comes from:

| KEY_SOURCE | How it works | Unattended? | Notes |
|---|---|---|---|
| `env` (default) | Reads a base64 key from `BACKUP_ENCRYPTION_KEY`. | Yes | Generate one with `python crypto_utils.py --generate-key`. |
| `prompt` | Prompts for a passphrase at startup; a key is derived via PBKDF2 (600,000 iterations) using a salt stored in `backup_salt.bin`. | No | Most explicit option; keep `backup_salt.bin` with your backups. |
| `keyfile` | Auto-generates a random key on first run and saves it (base64) to `%USERPROFILE%\.wolfpak_backup_key`. | Yes | Back up this file somewhere separate from the backup destination. |
| `dpapi` | Same as `keyfile`, but the key is encrypted with Windows DPAPI, tied to your Windows account, at `%USERPROFILE%\.wolfpak_backup_key.dpapi`. Requires `pywin32`. | Yes | Can only be unprotected from this Windows account on this machine. Export an offline copy with `python crypto_utils.py --export-key --key-source dpapi`. |

## Restoring a Backup

Encrypted files are written with a `.enc` suffix. To decrypt them, use `restore_backup.py` with the same `KEY_SOURCE` (and key/env var/salt file) the backup was originally written with:

```powershell
python restore_backup.py "E:\Automated_Backups" "C:\path\to\restore_here" --key-source env
```

This works on a single `.enc` file or a whole folder tree (folder mode walks recursively and preserves the relative structure, stripping the `.enc` suffix).

## Troubleshooting

### Error: Destination is not connected

- Confirm the drive letter or share path is correct in File Explorer.
- Update `TARGET_DRIVE_LETTER` in the script if your drive uses a different letter, or if pointing at an SMB share, confirm it's reachable.

### Error: Source folder does not exist

- Ensure a Desktop folder named `External Backup` exists.
- If using OneDrive Desktop, the script already checks that location first.

### Error: could not prepare encryption/destination

- For `KEY_SOURCE=env`, confirm `BACKUP_ENCRYPTION_KEY` is set and decodes to exactly 32 bytes.
- For S3/Azure, confirm credentials/connection string env vars are set and the endpoint uses HTTPS.

### python command not found

- Try `py` instead of `python`.
- Or install Python from python.org and ensure it is added to PATH.

## Notes

- This script runs continuously until you stop it.
- Every file is encrypted individually before upload; folder structure is preserved on the destination with each file suffixed `.enc`.
- Existing destination files/folders are overwritten cleanly on re-sync.
- Source items are moved to Recycle Bin only after the entire item (including all files in a folder) is successfully encrypted and uploaded.
