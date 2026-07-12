"""Decrypt files produced by backup_to_external_drive.py.

Usage:
    python restore_backup.py <encrypted_file_or_folder> <output_path> [--key-source SOURCE]

The --key-source (and matching env vars / key files) must match whatever
KEY_SOURCE the backup was originally written with, or decryption will fail.
"""

import argparse
import os

from crypto_utils import KeySource, decrypt_file, resolve_key


def restore_path(source: str, destination: str, key: bytes) -> None:
    if os.path.isdir(source):
        for root, _dirs, files in os.walk(source):
            for name in files:
                if not name.endswith(".enc"):
                    continue
                src_file = os.path.join(root, name)
                rel = os.path.relpath(src_file, source)
                dest_file = os.path.join(destination, rel[: -len(".enc")])
                decrypt_file(src_file, dest_file, key)
                print(f"Restored: {rel[:-len('.enc')]}")
    else:
        decrypt_file(source, destination, key)
        print(f"Restored: {destination}")


def main():
    parser = argparse.ArgumentParser(description="Decrypt WOLF-PAK encrypted backup files.")
    parser.add_argument("source", help="Encrypted .enc file, or a folder containing them, to restore")
    parser.add_argument("destination", help="Where to write the decrypted output")
    parser.add_argument(
        "--key-source",
        default=os.environ.get("KEY_SOURCE", KeySource.ENV),
        choices=KeySource.ALL,
        help="Must match the KEY_SOURCE the backup was written with.",
    )
    args = parser.parse_args()

    key = resolve_key(args.key_source)
    restore_path(args.source, args.destination, key)


if __name__ == "__main__":
    main()
