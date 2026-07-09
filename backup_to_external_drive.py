import os
import shutil
import time
from datetime import datetime
from send2trash import send2trash


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
TARGET_DRIVE_LETTER = "E:\\"
BACKUP_FOLDER_NAME = "Automated_Backups"

# How often the script runs after startup.
CHECK_INTERVAL_HOURS = 6
CHECK_INTERVAL_SECONDS = CHECK_INTERVAL_HOURS * 60 * 60
# =======================================================


def process_and_clear_folder():
    # 1. Verify the external hard drive is connected
    if not os.path.exists(TARGET_DRIVE_LETTER):
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Sync skipped: "
            f"External drive '{TARGET_DRIVE_LETTER}' is not connected."
        )
        return

    # 2. Verify the source directory exists
    if not os.path.exists(SOURCE_FOLDER):
        print(f"❌ Error: Source folder '{SOURCE_FOLDER}' does not exist.")
        return

    # Define the final destination path
    destination_path = os.path.join(TARGET_DRIVE_LETTER, BACKUP_FOLDER_NAME)
    os.makedirs(destination_path, exist_ok=True)

    # Scan the source folder
    items = os.listdir(SOURCE_FOLDER)
    if not items:
        return  # Stay quiet when empty to avoid log spam.

    print(f"\n🚀 [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] New items detected! Starting sync...")
    print(f"📦 Destination: {destination_path}")
    print("-" * 50)

    # 3. Process, copy, and then move source to Recycle Bin.
    for item_name in items:
        source_item = os.path.join(SOURCE_FOLDER, item_name)
        destination_item = os.path.join(destination_path, item_name)

        try:
            # Step A: Copy item to backup destination.
            if os.path.isdir(source_item):
                if os.path.exists(destination_item):
                    shutil.rmtree(destination_item)
                shutil.copytree(source_item, destination_item)
                print(f"✅ Copied Folder: {item_name}")
            else:
                shutil.copy2(source_item, destination_item)
                print(f"✅ Copied File:   {item_name}")

            # Step B: Only if copy succeeds, move source item to Recycle Bin.
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
    print(f"Backup target:   {os.path.join(TARGET_DRIVE_LETTER, BACKUP_FOLDER_NAME)}")
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