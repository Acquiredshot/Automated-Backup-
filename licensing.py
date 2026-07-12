"""Trial and license enforcement for Sentinel Backup.

Free for TRIAL_DAYS from first run. After that, run_once()/watch require a
valid license key - but verify, restore, and status never check this: a
customer can never be locked out of restoring their own already-encrypted
data, licensed or not.

License keys are minted internally by Wolf-Pak Innovations with a private
Ed25519 signing tool that isn't part of this repo. This module only ever
holds the matching PUBLIC key (below) and verifies signatures offline - no
network access, no phoning home. A key that verifies against this public
key is proof it was issued by Wolf-Pak Innovations and hasn't been altered.

Key format: "<base64url payload json>.<base64url signature>" (unpadded).

The trial-start timestamp is a plain local file, not a cryptographic
guarantee - see README for that limitation. The license signature check is
the real protection; the trial clock is an honor-system nicety on top of it.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TRIAL_DAYS = 7
CONTACT_EMAIL = "wolfpak_innovations@outlook.com"

# Wolf-Pak Innovations license-signing public key (Ed25519, raw 32 bytes, base64).
# The matching private key is held internally by Wolf-Pak Innovations and is
# never stored in this repo.
PUBLIC_KEY_B64 = "bl74pcN35TgUcoeyvDcoLT+LS+TOYZklz6fQLuHJ9RU="


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _state_dir() -> Path:
    return Path(os.path.expanduser("~")) / ".sentinel_license"


def _trial_start_path() -> Path:
    return _state_dir() / "trial_start"


def _license_key_path() -> Path:
    return _state_dir() / "license.key"


def get_trial_start() -> datetime:
    path = _trial_start_path()
    if path.exists():
        try:
            return datetime.fromisoformat(path.read_text().strip())
        except ValueError:
            pass
    _state_dir().mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    path.write_text(now.isoformat())
    return now


@dataclass
class LicenseInfo:
    customer: str
    plan: str
    billing: str
    issued: datetime
    expires: datetime

    @property
    def valid(self) -> bool:
        return datetime.now(timezone.utc) < self.expires


def verify_license_key(key_str: str) -> LicenseInfo:
    """Raises ValueError if the key is malformed or its signature doesn't check out."""
    parts = key_str.strip().split(".")
    if len(parts) != 2:
        raise ValueError("Malformed license key (expected payload.signature).")
    payload_b64, sig_b64 = parts

    try:
        payload_bytes = _b64u_decode(payload_b64)
        signature = _b64u_decode(sig_b64)
    except Exception as e:
        raise ValueError(f"Malformed license key: {e}")

    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY_B64))
    try:
        public_key.verify(signature, payload_bytes)
    except InvalidSignature:
        raise ValueError("License key signature is invalid.")

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
        return LicenseInfo(
            customer=payload["customer"],
            plan=payload["plan"],
            billing=payload["billing"],
            issued=datetime.fromisoformat(payload["issued"]),
            expires=datetime.fromisoformat(payload["expires"]),
        )
    except (KeyError, ValueError) as e:
        raise ValueError(f"License key payload is malformed: {e}")


def load_saved_license() -> LicenseInfo | None:
    path = _license_key_path()
    if not path.exists():
        return None
    try:
        return verify_license_key(path.read_text())
    except ValueError:
        return None


def save_license_key(key_str: str) -> LicenseInfo:
    """Validates the key before saving. Raises ValueError if it doesn't check out."""
    info = verify_license_key(key_str)
    _state_dir().mkdir(parents=True, exist_ok=True)
    _license_key_path().write_text(key_str.strip())
    return info


@dataclass
class AccessStatus:
    allowed: bool
    reason: str
    license: LicenseInfo | None
    trial_days_left: int


def check_access() -> AccessStatus:
    """Whether run_once()/watch are allowed to proceed right now.

    Never gates verify/restore/status - call this only from the paths that
    create new backups.
    """
    license_info = load_saved_license()
    if license_info and license_info.valid:
        return AccessStatus(
            True, f"Licensed to {license_info.customer} ({license_info.plan}/{license_info.billing})",
            license_info, 0,
        )

    trial_start = get_trial_start()
    elapsed_days = (datetime.now(timezone.utc) - trial_start).days
    days_left = TRIAL_DAYS - elapsed_days
    if elapsed_days < TRIAL_DAYS:
        return AccessStatus(True, f"Free trial - {days_left} day(s) left", license_info, days_left)

    expired_note = " (your license expired)" if license_info else ""
    return AccessStatus(
        False,
        f"Free trial ended{expired_note}. A Wolf-Pak Innovations subscription is required to run "
        f"new backups - contact {CONTACT_EMAIL}. verify/restore/status remain available regardless.",
        license_info, 0,
    )
