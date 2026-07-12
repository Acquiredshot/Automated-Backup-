"""At-rest encryption for backed-up files.

Files are encrypted with AES-256-GCM (authenticated: tampering or corruption
is detected on restore) in fixed-size chunks, so arbitrarily large files can
be streamed through without loading them fully into memory.

Container format written by encrypt_file():
    5 bytes   magic       b"WPBK1"
    1 byte    version     currently 1
    8 bytes   nonce_prefix (random, unique per file)
    4 bytes   chunk_size  (plaintext bytes per chunk, big-endian)
    repeated: 4 bytes ciphertext_len + ciphertext (AES-GCM, includes 16-byte tag)

The per-chunk nonce is nonce_prefix + a 4-byte big-endian chunk counter, so
nonces never repeat for a given file without depending on random collision.

Key management is pluggable via KeySource / resolve_key() so the same
encrypt/decrypt code works whether the key comes from an environment
variable, an interactive passphrase, a plain key file, or a Windows
DPAPI-protected key file.
"""

import argparse
import base64
import getpass
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"WPBK1"
VERSION = 1
CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB plaintext per chunk
NONCE_PREFIX_SIZE = 8
SALT_SIZE = 16
PBKDF2_ITERATIONS = 600_000


def generate_random_key() -> bytes:
    return os.urandom(32)


def _derive_key_from_passphrase(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    return kdf.derive(passphrase)


def _dpapi_protect(data: bytes) -> bytes:
    import win32crypt  # pywin32; Windows-only

    return win32crypt.CryptProtectData(data, "WOLF-PAK Backup Encryption Key", None, None, None, 0)


def _dpapi_unprotect(blob: bytes) -> bytes:
    import win32crypt  # pywin32; Windows-only

    _description, data = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
    return data


class KeySource:
    ENV = "env"
    PROMPT = "prompt"
    KEYFILE = "keyfile"
    DPAPI = "dpapi"

    ALL = (ENV, PROMPT, KEYFILE, DPAPI)


def resolve_key(
    key_source: str,
    *,
    env_var: str = "BACKUP_ENCRYPTION_KEY",
    key_file: str = None,
    passphrase_salt_file: str = None,
) -> bytes:
    """Returns the raw 32-byte AES-256 key for the configured KEY_SOURCE.

    KEYFILE and DPAPI modes auto-generate and persist a key on first use.
    """
    if key_source == KeySource.ENV:
        encoded = os.environ.get(env_var)
        if not encoded:
            raise RuntimeError(
                f"KEY_SOURCE is 'env' but environment variable {env_var} is not set. "
                f"Generate one with: python crypto_utils.py --generate-key"
            )
        key = base64.b64decode(encoded)
        if len(key) != 32:
            raise RuntimeError(f"{env_var} must decode to exactly 32 bytes (AES-256 key).")
        return key

    if key_source == KeySource.PROMPT:
        salt_path = Path(passphrase_salt_file or "backup_salt.bin")
        if salt_path.exists():
            salt = salt_path.read_bytes()
        else:
            salt = os.urandom(SALT_SIZE)
            salt_path.write_bytes(salt)
            print(
                f"New passphrase salt created at {salt_path}. Keep this file together with your "
                f"backups — without it, your passphrase cannot decrypt anything."
            )
        passphrase = getpass.getpass("Enter backup encryption passphrase: ").encode("utf-8")
        return _derive_key_from_passphrase(passphrase, salt)

    if key_source == KeySource.KEYFILE:
        path = Path(key_file or os.path.join(os.path.expanduser("~"), ".wolfpak_backup_key"))
        if path.exists():
            return base64.b64decode(path.read_bytes())
        key = generate_random_key()
        path.write_bytes(base64.b64encode(key))
        print(
            f"New encryption key generated and saved to {path}. Back this file up somewhere safe "
            f"and separate from the backup destination itself — losing it makes all encrypted "
            f"backups permanently unreadable."
        )
        return key

    if key_source == KeySource.DPAPI:
        path = Path(key_file or os.path.join(os.path.expanduser("~"), ".wolfpak_backup_key.dpapi"))
        if path.exists():
            return _dpapi_unprotect(path.read_bytes())
        key = generate_random_key()
        path.write_bytes(_dpapi_protect(key))
        print(
            f"New encryption key generated, protected with Windows DPAPI, and saved to {path}. "
            f"This key can only be unprotected from this Windows user account on this machine. "
            f"Keep an offline copy of the unprotected key (python crypto_utils.py --export-key "
            f"--key-source dpapi) in case you ever need to restore on another machine."
        )
        return key

    raise ValueError(f"Unknown KEY_SOURCE: {key_source}")


def encrypt_file(source_path: str, dest_path: str, key: bytes) -> None:
    aesgcm = AESGCM(key)
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)

    dest_dir = os.path.dirname(dest_path)
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)

    with open(source_path, "rb") as src, open(dest_path, "wb") as dst:
        dst.write(MAGIC)
        dst.write(struct.pack(">B", VERSION))
        dst.write(nonce_prefix)
        dst.write(struct.pack(">I", CHUNK_SIZE))

        chunk_index = 0
        while True:
            chunk = src.read(CHUNK_SIZE)
            if not chunk:
                break
            nonce = nonce_prefix + struct.pack(">I", chunk_index)
            ciphertext = aesgcm.encrypt(nonce, chunk, None)
            dst.write(struct.pack(">I", len(ciphertext)))
            dst.write(ciphertext)
            chunk_index += 1


def decrypt_file(source_path: str, dest_path: str, key: bytes) -> None:
    aesgcm = AESGCM(key)

    dest_dir = os.path.dirname(dest_path)
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)

    with open(source_path, "rb") as src, open(dest_path, "wb") as dst:
        magic = src.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError(f"{source_path} is not a recognized WOLF-PAK encrypted backup file.")
        src.read(1)  # version, unused for now
        nonce_prefix = src.read(NONCE_PREFIX_SIZE)
        src.read(4)  # chunk_size, informational only

        chunk_index = 0
        while True:
            length_bytes = src.read(4)
            if not length_bytes:
                break
            (length,) = struct.unpack(">I", length_bytes)
            ciphertext = src.read(length)
            nonce = nonce_prefix + struct.pack(">I", chunk_index)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            dst.write(plaintext)
            chunk_index += 1


def _main():
    parser = argparse.ArgumentParser(description="Key management helper for backup encryption.")
    parser.add_argument("--generate-key", action="store_true", help="Print a new base64 AES-256 key for KEY_SOURCE=env.")
    parser.add_argument("--export-key", action="store_true", help="Print the raw base64 key for a keyfile/dpapi KEY_SOURCE.")
    parser.add_argument("--key-source", default=KeySource.KEYFILE, choices=KeySource.ALL)
    parser.add_argument("--key-file", default=None)
    args = parser.parse_args()

    if args.generate_key:
        print(base64.b64encode(generate_random_key()).decode("ascii"))
        return

    if args.export_key:
        key = resolve_key(args.key_source, key_file=args.key_file)
        print(
            "WARNING: this is your raw decryption key in plaintext. Store it somewhere secure "
            "and offline; anyone with this key can decrypt every backup.",
        )
        print(base64.b64encode(key).decode("ascii"))
        return

    parser.print_help()


if __name__ == "__main__":
    _main()
