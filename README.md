# Auto Backup Script (Windows + External Drive)

A continuous Python sync script that watches your Desktop folder named **External Backup**, copies new items to **E:\Automated_Backups**, and then moves successfully copied source items to the Recycle Bin.

This Tool is designed for Intermediate to Advanced users and can be run directly from PowerShell (with or without VS Code).

## What This Script Does

- Detects your Desktop source folder, including OneDrive Desktop redirection.
- Checks that your external drive is connected.
- Creates the destination folder if it does not exist.
- Continuously watches the source folder on a timer.
- Copies files and folders from source to destination.
- Overwrites existing destination folders cleanly.
- Moves successfully copied source items to the Recycle Bin.
- Prints clear cycle-by-cycle logs.

## Project Structure

- `backup_to_external_drive.py` - Main backup script.

## Requirements

- Windows
- Python 3.8+
- External drive available as `E:\`
- Python package: `send2trash`

## Default Paths Used

- **Source folder name:** `External Backup`
- **Destination drive:** `E:\`
- **Destination folder name:** `Automated_Backups`
- **Final destination:** `E:\Automated_Backups`

## Quick Start

### 1. Clone or download this project

Place the folder anywhere on your computer.

### 2. Create your source folder on Desktop

Create a folder named:

- `External Backup`

Put any files/folders you want to back up into that folder.

### 3. Connect your external drive

Make sure your external drive is mounted as `E:\`.

### 4. Install dependency

```powershell
pip install send2trash
```

If `pip` is not recognized:

```powershell
py -m pip install send2trash
```

### 5. Run from PowerShell

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
Checking every 6 hours. Press Ctrl+C to stop.

🚀 [2026-07-09 10:17:46] New items detected! Starting sync...
📦 Destination: E:\Automated_Backups
--------------------------------------------------
✅ Copied File:   example.zip
🗑️  Moved to Recycle Bin: example.zip
✨ Sync cycle complete. Source folder is clear.
```

Stop the script any time with `Ctrl+C`.

## Configuration (Optional)

In `backup_to_external_drive.py`, edit these values if needed:

- `TARGET_DRIVE_LETTER` (example: `"E:\\"`)
- `BACKUP_FOLDER_NAME` (example: `"Automated_Backups"`)
- `CHECK_INTERVAL_HOURS` (example: `6`)

## Troubleshooting

### Error: External drive is not connected

- Confirm the drive letter is correct in File Explorer.
- Update `TARGET_DRIVE_LETTER` in the script if your drive uses a different letter.

### Error: Source folder does not exist

- Ensure a Desktop folder named `External Backup` exists.
- If using OneDrive Desktop, the script already checks that location first.

### python command not found

- Try `py` instead of `python`.
- Or install Python from python.org and ensure it is added to PATH.

## Notes

- This script runs continuously until you stop it.
- It copies items from source to destination.
- For folders, existing destination folders are removed and recopied.
- For files, existing files are overwritten.
- Source items are moved to Recycle Bin only after successful copy.
