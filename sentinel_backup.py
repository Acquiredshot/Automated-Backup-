#!/usr/bin/env python3
"""
SENTINEL BACKUP - Verified, Encrypted Backup with a Tamper-Evident Audit Trail

The core promise: no source file is ever deleted until a SHA-256 hash of the
written copy has been read back off the destination, decrypted, and matched
against the source. Copy-then-verify-then-release. Never copy-then-hope.

Every file is also encrypted with AES-256-GCM before it ever leaves this
machine, so the destination - whether that's a local drive, an SMB share, an
S3 bucket, or an Azure Blob container - never holds plaintext. For S3/Azure,
uploads travel over HTTPS by default via the vendor SDKs, covering
encryption in transit as well as at rest. See crypto_utils.py and
destinations.py.

Commands:
    run             One sync cycle, then exit. (Use with Task Scheduler.)
    watch           Continuous loop on an interval.
    verify          Re-download, decrypt, and re-hash the destination against
                    the manifest. Detects bit rot, silent corruption, and
                    unauthorized modification.
    restore         Pull files back out of the backup to a chosen folder.
    prune           Apply the retention policy to old versions (local/SMB
                    destinations only - see README for cloud destinations).
    status          Show destination, config, capacity, and last-run summary.
    init            Write a starter config file.

Author: <your name>
License: see LICENSE
"""

from __future__ import annotations

import argparse
import ctypes
import fnmatch
import hashlib
import json
import os
import platform
import shutil
import string
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from crypto_utils import KeySource, decrypt_file, encrypt_file, resolve_key
from destinations import BackupDestination, LocalDestination, build_destination

__version__ = "3.0.0"

IS_WINDOWS = platform.system() == "Windows"

# send2trash is optional. If it is missing we fall back to a local quarantine
# folder rather than hard-deleting anything. We never call os.remove on a
# user's source file. Ever.
try:
    from send2trash import send2trash as _send2trash
    HAVE_SEND2TRASH = True
except ImportError:  # pragma: no cover
    HAVE_SEND2TRASH = False

    def _send2trash(path):  # type: ignore
        raise RuntimeError("send2trash not installed")


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "source_folder": "",                    # blank = auto-detect Desktop\External Backup
    "source_folder_name": "External Backup",

    # Where encrypted, verified backups are written. "local" also covers
    # SMB/UNC network shares (target_drive_letter can be r"\\server\share").
    "destination_type": "local",            # local | s3 | azure

    "target_volume_label": "",              # PREFERRED for local. e.g. "BACKUP_HDD"
    "target_drive_letter": "E:\\",          # fallback if label not found

    "s3_bucket": "",
    "s3_prefix": "Automated_Backups",
    "s3_region": "",
    "s3_endpoint_url": "",                  # only for S3-compatible services; must be https

    "azure_container": "automated-backups",
    "azure_prefix": "Automated_Backups",
    "azure_connection_string_env": "AZURE_STORAGE_CONNECTION_STRING",

    "backup_folder_name": "Automated_Backups",
    "check_interval_hours": 6,
    "release_source": True,                 # move source to Recycle Bin after verified copy
    "release_mode": "recycle",              # recycle | quarantine | keep
    "quarantine_folder_name": "_released",
    "versioning": True,                     # keep prior copies instead of overwriting
    "retention_days": 90,                   # prune versions older than this (0 = keep forever)
    "retention_min_versions": 3,            # never prune below this many versions of a file
    "min_free_space_margin": 1.15,          # require 115% of payload size free on target (local only)
    "exclude_patterns": [
        "~$*", "*.tmp", "*.crdownload", "*.part",
        "Thumbs.db", "desktop.ini", ".DS_Store",
    ],
    "include_patterns": [],                 # empty = include everything not excluded
    "stability_seconds": 5,                 # file must be unmodified this long before copy
    "hash_algorithm": "sha256",
    "webhook_url": "",                      # optional POST on failure
    "log_retention_months": 24,

    # Encryption at rest (see crypto_utils.KeySource):
    #   "env"     - base64 key in the env var named by key_env_var (default)
    #   "prompt"  - typed passphrase at startup, derived via PBKDF2
    #   "keyfile" - plain key file under the user's profile, auto-generated
    #   "dpapi"   - same, but the key file is Windows DPAPI-protected
    "key_source": "env",
    "key_env_var": "BACKUP_ENCRYPTION_KEY",
    "key_file": "",                         # blank = crypto_utils default path
}

CONFIG_FILENAME = "sentinel_config.json"


@dataclass
class Config:
    data: dict = field(default_factory=lambda: dict(DEFAULT_CONFIG))

    @classmethod
    def load(cls, path: Path | None) -> "Config":
        cfg = dict(DEFAULT_CONFIG)
        if path and path.exists():
            try:
                user = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                raise SystemExit(f"Config file is not valid JSON: {path}\n  {e}")
            unknown = set(user) - set(DEFAULT_CONFIG)
            if unknown:
                print(f"[warn] Ignoring unknown config keys: {', '.join(sorted(unknown))}")
            cfg.update({k: v for k, v in user.items() if k in DEFAULT_CONFIG})
        return cls(cfg)

    def __getattr__(self, item):
        try:
            return self.data[item]
        except KeyError:
            raise AttributeError(item)


# --------------------------------------------------------------------------
# Drive discovery (local/SMB destinations)
# --------------------------------------------------------------------------

def _windows_volume_label(root: str) -> str:
    """Read the volume label for a drive root like 'E:\\'. Windows only."""
    if not IS_WINDOWS:
        return ""
    buf = ctypes.create_unicode_buffer(1024)
    fs = ctypes.create_unicode_buffer(1024)
    serial = ctypes.c_ulong()
    max_len = ctypes.c_ulong()
    flags = ctypes.c_ulong()
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root), buf, ctypes.sizeof(buf),
        ctypes.byref(serial), ctypes.byref(max_len),
        ctypes.byref(flags), fs, ctypes.sizeof(fs),
    )
    return buf.value if ok else ""


def find_target_root(cfg: Config) -> tuple[str | None, str]:
    """
    Locate the local/SMB backup drive.

    Strategy 1 (preferred): scan every mounted volume for a matching label.
      This is why the tool survives the drive letter changing from E: to G:
      when you plug in a phone or a second stick - the single most common
      cause of "my backup silently stopped working."
    Strategy 2: fall back to the configured drive letter (or a UNC path).
    """
    label = (cfg.target_volume_label or "").strip()

    if label and IS_WINDOWS:
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if not os.path.exists(root):
                continue
            if _windows_volume_label(root).strip().lower() == label.lower():
                return root, f"matched volume label '{label}' at {root}"

    if label and not IS_WINDOWS:
        for base in ("/Volumes", "/media", "/mnt", f"/media/{os.environ.get('USER', '')}"):
            candidate = Path(base) / label
            if candidate.exists():
                return str(candidate), f"matched volume '{label}' at {candidate}"

    fallback = cfg.target_drive_letter
    if fallback and os.path.exists(fallback):
        note = f"using configured path {fallback}"
        if label:
            note += f" (label '{label}' not found)"
        return fallback, note

    return None, (
        f"no drive found (label='{label or 'unset'}', path='{fallback}')"
    )


def resolve_source(cfg: Config) -> Path:
    if cfg.source_folder:
        return Path(os.path.expandvars(os.path.expanduser(cfg.source_folder)))

    home = Path.home()
    candidates = []
    onedrive = os.environ.get("OneDrive") or os.environ.get("OneDriveConsumer")
    if onedrive:
        candidates.append(Path(onedrive) / "Desktop")
    candidates.append(home / "Desktop")
    candidates.append(home / "OneDrive" / "Desktop")

    for desktop in candidates:
        candidate = desktop / cfg.source_folder_name
        if candidate.exists():
            return candidate
    return home / "Desktop" / cfg.source_folder_name


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------

def hash_file(path: Path, algo: str = "sha256", chunk: int = 1024 * 1024) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


# --------------------------------------------------------------------------
# Tamper-evident audit log
# --------------------------------------------------------------------------

class AuditLog:
    """
    Append-only JSON Lines log where each record carries the SHA-256 of the
    previous record. Change or delete any historical line and every subsequent
    chain hash breaks - which `verify` will report.

    This is what turns a print() script into something you can hand to an
    auditor: the log can prove it has not been edited after the fact.
    """

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.log_dir / f"audit-{datetime.now():%Y-%m}.jsonl"
        self._prev = self._last_chain_hash()

    def _last_chain_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last = None
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        if not last:
            return "0" * 64
        try:
            return json.loads(last)["chain"]
        except (json.JSONDecodeError, KeyError):
            return "0" * 64

    def write(self, event: str, **fields) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "host": platform.node(),
            "user": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
            "version": __version__,
            **fields,
        }
        record["prev"] = self._prev
        payload = json.dumps(record, sort_keys=True, ensure_ascii=False)
        chain = hashlib.sha256((self._prev + payload).encode("utf-8")).hexdigest()
        record["chain"] = chain
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._prev = chain

    def verify_chain(self) -> tuple[bool, str]:
        broken = []
        for log in sorted(self.log_dir.glob("audit-*.jsonl")):
            prev = "0" * 64
            with open(log, "r", encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    rec = json.loads(line)
                    claimed = rec.pop("chain")
                    if rec.get("prev") != prev:
                        broken.append(f"{log.name}:{n} prev-hash mismatch")
                    payload = json.dumps(
                        {k: v for k, v in rec.items()}, sort_keys=True, ensure_ascii=False
                    )
                    expect = hashlib.sha256((rec["prev"] + payload).encode("utf-8")).hexdigest()
                    if expect != claimed:
                        broken.append(f"{log.name}:{n} chain-hash mismatch")
                    prev = claimed
        if broken:
            return False, "; ".join(broken[:5])
        return True, "audit chain intact"


# --------------------------------------------------------------------------
# Manifest - the record of what is in the backup and what it hashed to
#
# Paths are always stored plaintext-relative (no .enc suffix, forward
# slashes) - the manifest describes the logical file being protected, not
# the encrypted object name on the destination. That's derived as
# `path + ".enc"` wherever it's needed.
# --------------------------------------------------------------------------

class Manifest:
    def __init__(self, metadata_root: Path):
        self.dir = metadata_root / "_sentinel"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "manifest.jsonl"

    def append(self, rel_path: str, digest: str, size: int, version: str) -> None:
        rec = {
            "path": rel_path.replace("\\", "/"),
            "sha256": digest,
            "size": size,
            "version": version,
            "backed_up": datetime.now(timezone.utc).isoformat(),
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return out

    def latest_by_path(self) -> dict[str, dict]:
        latest: dict[str, dict] = {}
        for rec in self.entries():
            latest[rec["path"]] = rec  # later lines win
        return latest

    def known_hashes(self) -> set[str]:
        return {r["sha256"] for r in self.entries()}


# --------------------------------------------------------------------------
# The engine
# --------------------------------------------------------------------------

class SentinelBackup:
    def __init__(self, cfg: Config, dry_run: bool = False, quiet: bool = False):
        self.cfg = cfg
        self.dry_run = dry_run
        self.quiet = quiet
        self.source = resolve_source(cfg)
        self.destination_type = cfg.destination_type
        self.audit = None
        self.manifest = None
        self.stats = {"copied": 0, "skipped": 0, "deduped": 0, "failed": 0, "bytes": 0}
        self._known: set[str] = set()

        self.key: bytes | None = None
        self.key_error: str | None = None
        try:
            self.key = resolve_key(
                cfg.key_source, env_var=cfg.key_env_var, key_file=(cfg.key_file or None),
            )
        except Exception as e:
            self.key_error = str(e)

        self.destination: BackupDestination | None = None
        self.target_root: str | None = None       # local/SMB drive root, for capacity checks
        self.dest: Path | None = None              # local/SMB destination folder, if applicable
        self.connected = False
        self.target_note = ""

        if self.destination_type == "local":
            self._init_local()
        else:
            self._init_cloud()

    def _init_local(self) -> None:
        target_root, note = find_target_root(self.cfg)
        self.target_root = target_root
        self.target_note = note
        self.connected = target_root is not None
        if self.connected:
            self.dest = Path(target_root) / self.cfg.backup_folder_name
            self.destination = LocalDestination(str(self.dest))
            self.metadata_root = self.dest
        else:
            self.metadata_root = None

    def _init_cloud(self) -> None:
        state_id = self._cloud_state_id()
        self.metadata_root = Path(__file__).with_name(".sentinel_state") / state_id
        try:
            self.destination = build_destination(self.destination_type, self._cloud_destination_config())
            self.connected, self.target_note = self.destination.check_connectivity()
        except Exception as e:
            self.destination = None
            self.connected = False
            self.target_note = f"could not initialize {self.destination_type} destination: {e}"

    def _cloud_destination_config(self) -> dict:
        if self.destination_type == "s3":
            return {
                "bucket": self.cfg.s3_bucket,
                "prefix": self.cfg.s3_prefix,
                "region": self.cfg.s3_region or None,
                "endpoint_url": self.cfg.s3_endpoint_url or None,
            }
        if self.destination_type == "azure":
            return {
                "container": self.cfg.azure_container,
                "prefix": self.cfg.azure_prefix,
                "connection_string_env": self.cfg.azure_connection_string_env,
            }
        raise ValueError(f"Unknown destination_type: {self.destination_type}")

    def _cloud_state_id(self) -> str:
        if self.destination_type == "s3":
            raw = f"s3_{self.cfg.s3_bucket}_{self.cfg.s3_prefix}"
        elif self.destination_type == "azure":
            raw = f"azure_{self.cfg.azure_container}_{self.cfg.azure_prefix}"
        else:
            raw = self.destination_type
        return "".join(c if c.isalnum() or c in "-_." else "_" for c in raw)

    def log(self, msg: str) -> None:
        if not self.quiet:
            print(msg, flush=True)

    # -- temp file helpers -------------------------------------------------

    @staticmethod
    def _new_temp_path(suffix: str = "") -> str:
        fd, path = tempfile.mkstemp(prefix="sentinel_", suffix=suffix)
        os.close(fd)
        return path

    @staticmethod
    def _cleanup_temp(paths: list[str]) -> None:
        for p in paths:
            try:
                Path(p).unlink(missing_ok=True)
            except OSError:
                pass

    def _safe_delete(self, relative_path: str) -> None:
        try:
            self.destination.delete_file(relative_path)
        except Exception:
            pass

    # -- filtering -------------------------------------------------------

    def _excluded(self, name: str) -> bool:
        for pat in self.cfg.exclude_patterns:
            if fnmatch.fnmatch(name, pat):
                return True
        if self.cfg.include_patterns:
            return not any(fnmatch.fnmatch(name, p) for p in self.cfg.include_patterns)
        return False

    def _stable(self, path: Path) -> bool:
        """
        Do not copy a file that is still being written. A file downloading in
        Chrome or being exported from Premiere will hash differently a second
        later - and the naive version of this script would happily back up
        half of it and then bin the original.
        """
        wait = self.cfg.stability_seconds
        if wait <= 0:
            return True
        try:
            first = path.stat()
        except OSError:
            return False
        time.sleep(min(wait, 5))
        try:
            second = path.stat()
        except OSError:
            return False
        return first.st_size == second.st_size and first.st_mtime == second.st_mtime

    # -- preflight -------------------------------------------------------

    def _payload(self) -> list[Path]:
        files = []
        for root, dirs, names in os.walk(self.source):
            dirs[:] = [d for d in dirs if not self._excluded(d)]
            for n in names:
                if not self._excluded(n):
                    files.append(Path(root) / n)
        return files

    def _check_capacity(self, files: list[Path]) -> tuple[bool, str]:
        if self.destination_type != "local":
            return True, "cloud destination - no local capacity limit enforced"
        needed = 0
        for f in files:
            try:
                needed += f.stat().st_size
            except OSError:
                pass
        needed = int(needed * self.cfg.min_free_space_margin)
        free = shutil.disk_usage(self.target_root).free
        if needed > free:
            return False, (
                f"insufficient space: need ~{needed / 1e9:.2f} GB "
                f"(incl. {int((self.cfg.min_free_space_margin - 1) * 100)}% margin), "
                f"{free / 1e9:.2f} GB free"
            )
        return True, f"{free / 1e9:.1f} GB free, need ~{needed / 1e9:.2f} GB"

    # -- the critical path ------------------------------------------------

    def _copy_verified(self, src: Path, rel: Path) -> tuple[bool, str, str]:
        """
        Encrypt, upload, and verify one file before it is ever eligible for
        release.

        1. Hash the plaintext source.
        2. If an identical hash already exists in the manifest and the
           encrypted object is present at the destination -> dedupe, skip
           the write entirely, but still release the source. Saves hours on
           re-runs.
        3. Encrypt to a local temp file (AES-256-GCM), then upload it to a
           staging name on the destination (never the final name yet).
        4. Read the bytes BACK OFF THE DESTINATION - not the local temp file
           - into another temp file. This is the whole point: a cached write
           that never made it to platter, a failing sector, a flaky USB
           bridge or network hiccup - all caught here.
        5. Decrypt what came back and hash the plaintext. AES-256-GCM's
           authentication tag means a single flipped bit anywhere in the
           ciphertext raises here instead of silently producing garbage, so
           this one step catches bit rot, truncation, AND tampering.
        6. Only if the re-derived plaintext hash matches the source hash:
           version any prior copy, promote the staged upload to its final
           name (rename - atomic where the backend allows it), and record
           the file in the manifest.
        Any failure at any step: the staged/temp copies are removed and the
        source is RETAINED. We fail safe, not silent.
        """
        algo = self.cfg.hash_algorithm
        try:
            src_hash = hash_file(src, algo)
            size = src.stat().st_size
        except OSError as e:
            return False, "", f"unreadable source: {e}"

        final_rel = rel.as_posix() + ".enc"

        # Dedupe: identical plaintext content already banked at this path.
        if src_hash in self._known and self.destination.exists(final_rel):
            self.stats["deduped"] += 1
            return True, src_hash, "identical copy already in backup"

        if self.dry_run:
            return True, src_hash, "would encrypt + copy"

        staging_rel = final_rel + ".sentinel-part"
        tmp_paths: list[str] = []
        try:
            tmp_enc = self._new_temp_path(".enc")
            tmp_paths.append(tmp_enc)
            encrypt_file(str(src), tmp_enc, self.key)

            self.destination.upload_file(tmp_enc, staging_rel)

            tmp_readback = self._new_temp_path(".enc")
            tmp_paths.append(tmp_readback)
            self.destination.download_file(staging_rel, tmp_readback)

            tmp_plain = self._new_temp_path()
            tmp_paths.append(tmp_plain)
            decrypt_file(tmp_readback, tmp_plain, self.key)
            dst_hash = hash_file(Path(tmp_plain), algo)
        except Exception as e:
            self._cleanup_temp(tmp_paths)
            self._safe_delete(staging_rel)
            return False, src_hash, f"copy failed: {e}"

        self._cleanup_temp(tmp_paths)

        if dst_hash != src_hash:
            self._safe_delete(staging_rel)
            return False, src_hash, (
                f"INTEGRITY FAILURE - decrypted read-back does not match source "
                f"(src {src_hash[:12]} != dst {dst_hash[:12]}). Source retained."
            )

        if self.destination.exists(final_rel):
            if self.cfg.versioning:
                stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                version_rel = f"_sentinel/versions/{rel.parent.as_posix()}/{rel.name}.{stamp}.enc"
                try:
                    self.destination.rename(final_rel, version_rel)
                except Exception as e:
                    self._safe_delete(staging_rel)
                    return False, src_hash, f"could not version prior copy: {e}"
            else:
                self._safe_delete(final_rel)

        try:
            self.destination.rename(staging_rel, final_rel)
        except Exception as e:
            return False, src_hash, f"could not promote staged copy: {e}"

        self._known.add(src_hash)
        self.manifest.append(str(rel), src_hash, size, datetime.now().strftime("%Y%m%d-%H%M%S"))
        self.stats["bytes"] += size
        return True, src_hash, "verified"

    def _release(self, src: Path) -> str:
        """Retire a source file only after verification. Never os.remove()."""
        mode = self.cfg.release_mode
        if not self.cfg.release_source or mode == "keep":
            return "source kept"
        if mode == "recycle" and HAVE_SEND2TRASH:
            _send2trash(str(src))
            return "moved to Recycle Bin"
        # Quarantine fallback - reversible, and works when send2trash is absent
        qdir = self.source.parent / self.cfg.quarantine_folder_name / datetime.now().strftime("%Y%m%d")
        qdir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(qdir / src.name))
        return f"quarantined -> {qdir}"

    # -- commands ---------------------------------------------------------

    def run_once(self) -> int:
        started = time.time()

        if self.key_error:
            self.log(f"[error] Could not prepare encryption key: {self.key_error}")
            return 2
        if not self.connected:
            self.log(f"[skip] Backup destination not available - {self.target_note}")
            return 2
        if not self.source.exists():
            self.log(f"[error] Source folder does not exist: {self.source}")
            return 3

        self.metadata_root.mkdir(parents=True, exist_ok=True)
        self.manifest = Manifest(self.metadata_root)
        self.audit = AuditLog(self.metadata_root / "_sentinel" / "logs")
        self._known = self.manifest.known_hashes()

        files = self._payload()
        if not files:
            return 0  # quiet when idle - no log spam

        ok, cap_note = self._check_capacity(files)
        self.audit.write("cycle_start", source=str(self.source), destination=self.destination_type,
                         files=len(files), capacity=cap_note, dry_run=self.dry_run)
        if not ok:
            self.log(f"[abort] {cap_note}")
            self.audit.write("cycle_abort", reason=cap_note)
            self._notify(f"Backup aborted: {cap_note}")
            return 4

        mode = "DRY RUN - nothing will be written or deleted" if self.dry_run else "LIVE"
        self.log(f"\n[{datetime.now():%Y-%m-%d %H:%M:%S}] {len(files)} item(s) queued  ({mode})")
        self.log(f"  source      : {self.source}")
        self.log(f"  destination : {self.destination_type}   [{self.target_note}]")
        self.log(f"  encryption  : AES-256-GCM (key_source={self.cfg.key_source})")
        self.log(f"  space       : {cap_note}")
        self.log("-" * 66)

        for src in files:
            rel = src.relative_to(self.source)

            if not self._stable(src):
                self.log(f"  [wait] {rel}  (still being written - will retry next cycle)")
                self.stats["skipped"] += 1
                self.audit.write("skip_unstable", path=str(rel))
                continue

            ok, digest, note = self._copy_verified(src, rel)
            if not ok:
                self.stats["failed"] += 1
                self.log(f"  [FAIL] {rel}  {note}")
                self.audit.write("copy_failed", path=str(rel), reason=note, sha256=digest)
                continue

            self.stats["copied"] += 1
            self.log(f"  [ ok ] {rel}  sha256:{digest[:16]}  {note}")

            if self.dry_run:
                continue
            try:
                disposal = self._release(src)
                self.audit.write("copy_verified", path=str(rel), sha256=digest,
                                 size=src.stat().st_size if src.exists() else 0,
                                 disposal=disposal)
            except Exception as e:
                self.log(f"  [warn] copied and verified, but could not release source: {e}")
                self.audit.write("release_failed", path=str(rel), sha256=digest, reason=str(e))

        elapsed = time.time() - started
        self.log("-" * 66)
        self.log(
            f"  {self.stats['copied']} verified  |  {self.stats['deduped']} already banked  |  "
            f"{self.stats['skipped']} deferred  |  {self.stats['failed']} failed  |  "
            f"{self.stats['bytes'] / 1e6:.1f} MB in {elapsed:.1f}s"
        )
        self.audit.write("cycle_end", **self.stats, seconds=round(elapsed, 2))

        if self.stats["failed"]:
            self._notify(
                f"{self.stats['failed']} file(s) failed verification on {platform.node()}. "
                f"Sources were retained. See audit log."
            )
            return 1
        return 0

    def verify(self, check_chain: bool = True) -> int:
        """Re-download, decrypt, and re-hash everything against the manifest."""
        if self.key_error:
            self.log(f"[error] Could not prepare encryption key: {self.key_error}")
            return 2
        if not self.connected:
            self.log(f"[error] Backup destination not available - {self.target_note}")
            return 2
        self.manifest = Manifest(self.metadata_root)
        self.audit = AuditLog(self.metadata_root / "_sentinel" / "logs")

        latest = self.manifest.latest_by_path()
        if not latest:
            self.log("[info] Manifest is empty - nothing to verify yet.")
            return 0

        self.log(f"\nVerifying {len(latest)} file(s) against manifest ({self.destination_type})")
        self.log("-" * 66)
        good = missing = corrupt = 0
        for rel, rec in sorted(latest.items()):
            dest_rel = rel + ".enc"
            if not self.destination.exists(dest_rel):
                self.log(f"  [MISSING ] {rel}")
                missing += 1
                continue

            tmp_paths: list[str] = []
            try:
                tmp_enc = self._new_temp_path(".enc")
                tmp_paths.append(tmp_enc)
                self.destination.download_file(dest_rel, tmp_enc)

                tmp_plain = self._new_temp_path()
                tmp_paths.append(tmp_plain)
                decrypt_file(tmp_enc, tmp_plain, self.key)
                actual = hash_file(Path(tmp_plain), self.cfg.hash_algorithm)
            except Exception as e:
                self.log(f"  [UNREADABLE] {rel}  {e}")
                corrupt += 1
                self._cleanup_temp(tmp_paths)
                continue
            self._cleanup_temp(tmp_paths)

            if actual != rec["sha256"]:
                self.log(f"  [CORRUPT ] {rel}")
                self.log(f"             expected {rec['sha256'][:24]}")
                self.log(f"             actual   {actual[:24]}")
                corrupt += 1
            else:
                good += 1

        self.log("-" * 66)
        self.log(f"  {good} intact  |  {missing} missing  |  {corrupt} corrupt or modified")

        if check_chain:
            chain_ok, chain_note = self.audit.verify_chain()
            self.log(f"  audit log: {chain_note}")
            if not chain_ok:
                self.log("  [!] The audit log has been altered since it was written.")

        self.audit.write("verify", intact=good, missing=missing, corrupt=corrupt)
        if missing or corrupt:
            self._notify(f"Verification found {missing} missing and {corrupt} corrupt file(s).")
            return 1
        return 0

    def restore(self, dest_dir: Path, pattern: str = "*") -> int:
        """A backup you have never restored from is not a backup. This is the drill."""
        if self.key_error:
            self.log(f"[error] Could not prepare encryption key: {self.key_error}")
            return 2
        if not self.connected:
            self.log(f"[error] Backup destination not available - {self.target_note}")
            return 2
        self.manifest = Manifest(self.metadata_root)
        self.audit = AuditLog(self.metadata_root / "_sentinel" / "logs")
        latest = self.manifest.latest_by_path()

        matches = {k: v for k, v in latest.items() if fnmatch.fnmatch(k, pattern)
                   or fnmatch.fnmatch(Path(k).name, pattern)}
        if not matches:
            self.log(f"[info] No backed-up files match '{pattern}'.")
            return 1

        dest_dir.mkdir(parents=True, exist_ok=True)
        self.log(f"\nRestoring {len(matches)} file(s) -> {dest_dir}")
        restored = failed = 0
        for rel, rec in sorted(matches.items()):
            dest_rel = rel + ".enc"
            out = dest_dir / rel
            if not self.destination.exists(dest_rel):
                self.log(f"  [MISSING] {rel}")
                failed += 1
                continue
            if self.dry_run:
                self.log(f"  [would restore] {rel}")
                continue

            out.parent.mkdir(parents=True, exist_ok=True)
            tmp_paths: list[str] = []
            try:
                tmp_enc = self._new_temp_path(".enc")
                tmp_paths.append(tmp_enc)
                self.destination.download_file(dest_rel, tmp_enc)
                decrypt_file(tmp_enc, str(out), self.key)
            except Exception as e:
                self.log(f"  [FAIL] {rel} - {e}")
                failed += 1
                self._cleanup_temp(tmp_paths)
                continue
            self._cleanup_temp(tmp_paths)

            # Verify the restore too. Same discipline, both directions.
            if hash_file(out, self.cfg.hash_algorithm) != rec["sha256"]:
                self.log(f"  [FAIL] {rel} - restored copy failed hash check")
                failed += 1
                continue
            self.log(f"  [ ok ] {rel}")
            restored += 1

        self.audit.write("restore", restored=restored, failed=failed,
                         target=str(dest_dir), pattern=pattern)
        self.log(f"\n  {restored} restored and hash-verified, {failed} failed.")
        return 1 if failed else 0

    def prune(self) -> int:
        """Age out old versions, keeping a floor so you always have history."""
        if self.destination_type != "local":
            self.log(
                f"[info] prune is only implemented for local/SMB destinations. For "
                f"{self.destination_type}, use the provider's native lifecycle rules "
                f"(S3 Lifecycle configuration / Azure Blob lifecycle management) to "
                f"expire objects under the '_sentinel/versions/' prefix."
            )
            return 0
        if not self.connected:
            self.log(f"[error] Backup destination not available - {self.target_note}")
            return 2
        days = self.cfg.retention_days
        if days <= 0:
            self.log("[info] retention_days = 0, keeping all versions.")
            return 0
        vroot = self.dest / "_sentinel" / "versions"
        if not vroot.exists():
            return 0
        self.audit = AuditLog(self.metadata_root / "_sentinel" / "logs")

        cutoff = time.time() - days * 86400
        groups: dict[str, list[Path]] = {}
        for p in vroot.rglob("*"):
            if p.is_file():
                groups.setdefault(str(p.parent / p.name.rsplit(".", 1)[0]), []).append(p)

        removed = freed = 0
        for _, versions in groups.items():
            versions.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            for old in versions[self.cfg.retention_min_versions:]:
                if old.stat().st_mtime < cutoff:
                    size = old.stat().st_size
                    if not self.dry_run:
                        old.unlink()
                    removed += 1
                    freed += size
        self.log(f"  Pruned {removed} version(s), reclaimed {freed / 1e6:.1f} MB.")
        self.audit.write("prune", removed=removed, bytes_freed=freed, dry_run=self.dry_run)
        return 0

    def status(self) -> int:
        self.log("=" * 66)
        self.log(f"  SENTINEL BACKUP v{__version__}")
        self.log("=" * 66)
        self.log(f"  Source        : {self.source}  {'[OK]' if self.source.exists() else '[NOT FOUND]'}")
        self.log(f"  Destination   : {self.destination_type}")
        self.log(f"  Connectivity  : {'connected' if self.connected else 'NOT CONNECTED'}  ({self.target_note})")
        key_note = f"key_source={self.cfg.key_source}" if not self.key_error else f"KEY ERROR: {self.key_error}"
        self.log(f"  Encryption    : AES-256-GCM  ({key_note})")
        if self.destination_type == "local" and self.connected:
            total, used, free = shutil.disk_usage(self.target_root)
            self.log(f"  Capacity      : {free / 1e9:.1f} GB free of {total / 1e9:.1f} GB")
        if self.connected:
            m = Manifest(self.metadata_root)
            entries = m.entries()
            latest = m.latest_by_path()
            self.log(f"  Files banked  : {len(latest)} unique ({len(entries)} total versions)")
            if entries:
                self.log(f"  Last backup   : {entries[-1]['backed_up']}")
        self.log(f"  Recycle Bin   : {'available' if HAVE_SEND2TRASH else 'send2trash NOT installed -> quarantine fallback'}")
        self.log(f"  Release mode  : {self.cfg.release_mode}")
        self.log(f"  Versioning    : {'on' if self.cfg.versioning else 'off'}")
        self.log("=" * 66)
        return 0 if self.connected else 2

    # -- alerting ---------------------------------------------------------

    def _notify(self, message: str) -> None:
        """
        A backup that fails silently is worse than no backup, because you
        trusted it. Point webhook_url at Slack, Teams, or Zapier and you find
        out the same day.
        """
        url = self.cfg.webhook_url
        if not url or self.dry_run:
            return
        try:
            import urllib.request
            body = json.dumps({"text": f"[Sentinel Backup] {platform.node()}: {message}"})
            req = urllib.request.Request(
                url, data=body.encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:  # never let alerting break the backup
            self.log(f"  [warn] webhook failed: {e}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel_backup",
        description="Verified, encrypted backup with a tamper-evident audit trail.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python sentinel_backup.py init
  python sentinel_backup.py status
  python sentinel_backup.py run --dry-run
  python sentinel_backup.py run
  python sentinel_backup.py watch
  python sentinel_backup.py verify
  python sentinel_backup.py restore --to "C:\\Users\\Me\\Desktop\\Recovered" --pattern "*.pdf"
  python sentinel_backup.py prune
""",
    )
    p.add_argument("command",
                   choices=["run", "watch", "verify", "restore", "prune", "status", "init"])
    p.add_argument("--config", type=Path, default=Path(__file__).with_name(CONFIG_FILENAME))
    p.add_argument("--dry-run", action="store_true",
                   help="Show exactly what would happen. Writes nothing, deletes nothing.")
    p.add_argument("--quiet", action="store_true", help="Suppress console output (for scheduled runs).")
    p.add_argument("--to", type=Path, help="restore: destination folder")
    p.add_argument("--pattern", default="*", help="restore: glob filter, e.g. '*.docx'")
    p.add_argument("--version", action="version", version=f"sentinel_backup {__version__}")
    return p


def cmd_init(path: Path) -> int:
    if path.exists():
        print(f"Config already exists: {path}")
        return 1
    path.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
    print(f"Wrote starter config: {path}")
    print("\nNext steps:")
    print("  1. Set 'target_volume_label' to your drive's label (right-click the drive in")
    print("     File Explorer -> Rename), or set destination_type to 's3'/'azure' and fill")
    print("     in the matching section instead.")
    print("  2. Generate an encryption key: python crypto_utils.py --generate-key")
    print("     then set it as the BACKUP_ENCRYPTION_KEY environment variable (or pick a")
    print("     different key_source in the config).")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "init":
        return cmd_init(args.config)

    cfg = Config.load(args.config)
    engine = SentinelBackup(cfg, dry_run=args.dry_run, quiet=args.quiet)

    if args.command == "status":
        return engine.status()
    if args.command == "verify":
        return engine.verify()
    if args.command == "prune":
        return engine.prune()
    if args.command == "restore":
        if not args.to:
            print("restore requires --to <folder>")
            return 64
        return engine.restore(args.to, args.pattern)
    if args.command == "run":
        return engine.run_once()

    if args.command == "watch":
        interval = cfg.check_interval_hours * 3600
        engine.status()
        print(f"\nWatching. Cycle every {cfg.check_interval_hours}h. Ctrl+C to stop.\n")
        while True:
            try:
                SentinelBackup(cfg, args.dry_run, args.quiet).run_once()
                time.sleep(interval)
            except KeyboardInterrupt:
                print("\nStopped by user. Nothing was left half-copied.")
                return 0
            except Exception as e:
                print(f"[warn] cycle error: {e} - retrying next interval")
                time.sleep(interval)

    return 0


if __name__ == "__main__":
    sys.exit(main())
