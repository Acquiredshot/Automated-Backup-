import os
import tempfile
import time
from datetime import datetime

from send2trash import send2trash

from crypto_utils import KeySource, encrypt_file, resolve_key
from destinations import build_destination


def get_external_backup_source_folder():
    # Support both local Desktop and OneDrive-redirected Desktop locations.
    home = os.path.expanduser("~")
    candidates = [os.path.join(home, "Desktop")]

    onedrive_root = os.environ.get("OneDrive")
    if onedrive_root:
        candidates.insert(0, os.path.join(onedrive_root, "Desktop"))

    for desktop_path in candidates:
        source_candidate = os.path.join(desktop_path, "External Backup")
        if os.path.exists(source_candidate):
            return source_candidate

    # Default to local Desktop path if none exist yet.
    return os.path.join(home, "Desktop", "External Backup")

# ==================== CONFIGURATION ====================
SOURCE_FOLDER = get_external_backup_source_folder()

# Where encrypted backups are written. "local" also covers SMB/UNC network
# shares (e.g. TARGET_DRIVE_LETTER = r"\\server\share") since Windows
# handles those like ordinary paths. "s3" and "azure" upload over HTTPS.
DESTINATION_TYPE = os.environ.get("BACKUP_DESTINATION_TYPE", "local")

# --- local / SMB destination config ---
TARGET_DRIVE_LETTER = "E:\\"
BACKUP_FOLDER_NAME = "Automated_Backups"

# --- S3 destination config (used when DESTINATION_TYPE == "s3") ---
S3_BUCKET = os.environ.get("BACKUP_S3_BUCKET", "")
S3_PREFIX = "Automated_Backups"
S3_REGION = os.environ.get("AWS_REGION")
S3_ENDPOINT_URL = os.environ.get("BACKUP_S3_ENDPOINT_URL")  # for S3-compatible services; must be https

# --- Azure Blob destination config (used when DESTINATION_TYPE == "azure") ---
AZURE_CONTAINER = os.environ.get("BACKUP_AZURE_CONTAINER", "automated-backups")
AZURE_PREFIX = "Automated_Backups"

# How the AES-256 encryption key is sourced. See crypto_utils.KeySource:
#   "env"     - base64 key in BACKUP_ENCRYPTION_KEY env var (default)
#   "prompt"  - typed passphrase at startup, derived via PBKDF2
#   "keyfile" - plain key file under the user's profile, auto-generated
#   "dpapi"   - same, but the key file is Windows DPAPI-protected
KEY_SOURCE = os.environ.get("KEY_SOURCE", KeySource.ENV)

# How often the script runs after startup.
CHECK_INTERVAL_HOURS = 6
CHECK_INTERVAL_SECONDS = CHECK_INTERVAL_HOURS * 60 * 60
# =======================================================


def _destination_config():
    if DESTINATION_TYPE == "local":
        return {"root_path": os.path.join(TARGET_DRIVE_LETTER, BACKUP_FOLDER_NAME)}
    if DESTINATION_TYPE == "s3":
        return {
            "bucket": S3_BUCKET,
            "prefix": S3_PREFIX,
            "region": S3_REGION,
            "endpoint_url": S3_ENDPOINT_URL,
        }
    if DESTINATION_TYPE == "azure":
        return {"container": AZURE_CONTAINER, "prefix": AZURE_PREFIX}
    raise ValueError(f"Unknown DESTINATION_TYPE: {DESTINATION_TYPE}")


def _describe_destination():
    if DESTINATION_TYPE == "local":
        return os.path.join(TARGET_DRIVE_LETTER, BACKUP_FOLDER_NAME)
    if DESTINATION_TYPE == "s3":
        return f"s3://{S3_BUCKET}/{S3_PREFIX}"
    if DESTINATION_TYPE == "azure":
        return f"azure-blob://{AZURE_CONTAINER}/{AZURE_PREFIX}"
    return DESTINATION_TYPE


def _encrypt_and_upload_file(local_source_file, relative_path, destination, key):
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="wolfpak_", suffix=".enc")
    os.close(tmp_fd)
    try:
        encrypt_file(local_source_file, tmp_path, key)
        destination.upload_file(tmp_path, relative_path + ".enc")
    finally:
        os.remove(tmp_path)


def _process_item(source_item, item_name, destination, key):
    if os.path.isdir(source_item):
        for root, _dirs, files in os.walk(source_item):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                relative_path = os.path.join(item_name, os.path.relpath(file_path, source_item))
                _encrypt_and_upload_file(file_path, relative_path, destination, key)
        print(f"✅ Encrypted + uploaded folder: {item_name}")
    else:
        _encrypt_and_upload_file(source_item, item_name, destination, key)
        print(f"✅ Encrypted + uploaded file:   {item_name}")


def process_and_clear_folder():
    # 1. For local/SMB destinations, verify the drive/share is reachable.
    if DESTINATION_TYPE == "local" and not os.path.exists(TARGET_DRIVE_LETTER):
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Sync skipped: "
            f"Destination '{TARGET_DRIVE_LETTER}' is not connected."
        )
        return

    # 2. Verify the source directory exists
    if not os.path.exists(SOURCE_FOLDER):
        print(f"❌ Error: Source folder '{SOURCE_FOLDER}' does not exist.")
        return

    # Scan the source folder
    items = os.listdir(SOURCE_FOLDER)
    if not items:
        return  # Stay quiet when empty to avoid log spam.

    # 3. Resolve the encryption key and destination backend for this cycle.
    try:
        key = resolve_key(KEY_SOURCE)
        destination = build_destination(DESTINATION_TYPE, _destination_config())
    except Exception as e:
        print(f"❌ Sync skipped: could not prepare encryption/destination. Error: {e}")
        return

    print(f"\n🚀 [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] New items detected! Starting sync...")
    print(f"📦 Destination: {_describe_destination()} (encrypted at rest, AES-256-GCM)")
    print("-" * 50)

    # 4. Encrypt, upload, and then move source to Recycle Bin only on success.
    for item_name in items:
        source_item = os.path.join(SOURCE_FOLDER, item_name)

        try:
            _process_item(source_item, item_name, destination, key)
            send2trash(source_item)
            print(f"🗑️  Moved to Recycle Bin: {item_name}")

        except Exception as e:
            print(f"❌ Failed to process {item_name}. Retaining source file. Error: {e}")

    print("✨ Sync cycle complete. Source folder is clear.\n")


def main():
    print("=" * 60)
    print("      WOLF-PAK FILE SYSTEM SHIELD - AUTOMATED SYNC")
    print("=" * 60)
    print(f"Watching folder: {SOURCE_FOLDER}")
    print(f"Backup target:   {_describe_destination()}")
    print(f"Encryption:      AES-256-GCM at rest (KEY_SOURCE={KEY_SOURCE})")
    print("Runs one sync immediately, then follows the schedule.")
    print(f"Checking every {CHECK_INTERVAL_HOURS} hours. Press Ctrl+C to stop.\n")

    # Continuous scheduling loop
    while True:
        try:
            process_and_clear_folder()
            time.sleep(CHECK_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            print("\n👋 Automation stopped safely by user.")
            break
        except Exception as e:
            print(f"⚠️ Unexpected loop error: {e}")
            time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
