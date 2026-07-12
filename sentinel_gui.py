#!/usr/bin/env python3
"""
SENTINEL BACKUP - GUI control panel

A PySide6 front end over sentinel_backup.py. It does not reimplement any
backup logic - every action (run, verify, restore, prune, status) calls
straight into SentinelBackup, with that engine's log() method redirected
to a Qt signal so output streams into the window instead of a console.

Only one engine action runs at a time; buttons are disabled while busy so
two operations can never touch the same manifest/audit files concurrently.

Launch with: python sentinel_gui.py  (or pythonw sentinel_gui.py for no
console window alongside it).
"""

from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

import crypto_utils
import licensing
from sentinel_backup import CONFIG_FILENAME, DEFAULT_CONFIG, Config, SentinelBackup

SCRIPT_DIR = Path(__file__).parent
DEFAULT_CONFIG_PATH = SCRIPT_DIR / CONFIG_FILENAME
INSTALL_SCRIPT_PATH = SCRIPT_DIR / "Install-SentinelTask.ps1"
MONOSPACE = QFont("Consolas", 9)


def load_config_dict(path: Path) -> dict:
    if not path.exists():
        path.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
    return Config.load(path).data


# --------------------------------------------------------------------------
# Workers - run blocking work off the UI thread, stream output back via signals
# --------------------------------------------------------------------------

class EngineWorker(QObject):
    """Runs one SentinelBackup action in a background thread."""

    log_line = Signal(str)
    finished = Signal(int)

    def __init__(self, config_path: Path, action: str, dry_run: bool = False, **kwargs):
        super().__init__()
        self.config_path = config_path
        self.action = action
        self.dry_run = dry_run
        self.kwargs = kwargs

    def run(self) -> None:
        code = 99
        try:
            cfg = Config.load(self.config_path)
            engine = SentinelBackup(cfg, dry_run=self.dry_run, quiet=False)
            engine.log = lambda msg: self.log_line.emit(msg)  # redirect print() -> signal

            if self.action == "run":
                code = engine.run_once()
            elif self.action == "verify":
                code = engine.verify()
            elif self.action == "prune":
                code = engine.prune()
            elif self.action == "status":
                code = engine.status()
            elif self.action == "restore":
                code = engine.restore(self.kwargs["dest_dir"], self.kwargs.get("pattern", "*"))
            else:
                raise ValueError(f"Unknown action: {self.action}")
        except Exception as e:
            self.log_line.emit(f"[fatal] {e}")
        self.finished.emit(code)


class ProcessWorker(QObject):
    """Streams stdout/stderr from an external command (used for PowerShell)."""

    log_line = Signal(str)
    finished = Signal(int)

    def __init__(self, args: list[str]):
        super().__init__()
        self.args = args

    def run(self) -> None:
        try:
            proc = subprocess.Popen(
                self.args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, cwd=str(SCRIPT_DIR),
            )
            for line in proc.stdout:
                self.log_line.emit(line.rstrip("\n"))
            proc.wait()
            self.finished.emit(proc.returncode)
        except Exception as e:
            self.log_line.emit(f"[fatal] {e}")
            self.finished.emit(99)


# --------------------------------------------------------------------------
# Dashboard tab
# --------------------------------------------------------------------------

class DashboardTab(QWidget):
    def __init__(self, main_window: "MainWindow"):
        super().__init__()
        self.main_window = main_window

        self.license_label = QLabel()
        self.license_label.setWordWrap(True)
        self.license_key_edit = QLineEdit()
        self.license_key_edit.setPlaceholderText("Paste a license key from Wolf-Pak Innovations")
        activate_btn = QPushButton("Activate")
        activate_btn.clicked.connect(self._activate_license)
        license_row = QHBoxLayout()
        license_row.addWidget(self.license_key_edit, stretch=1)
        license_row.addWidget(activate_btn)

        self.status_view = QPlainTextEdit(readOnly=True)
        self.status_view.setFont(MONOSPACE)
        self.status_view.setPlaceholderText("Click Refresh Status to check the destination.")

        self.dry_run_box = QCheckBox("Dry run (writes nothing, deletes nothing)")

        refresh_btn = QPushButton("Refresh Status")
        self.run_btn = QPushButton("Run Backup Now")
        verify_btn = QPushButton("Verify Archive")
        prune_btn = QPushButton("Prune Old Versions")

        refresh_btn.clicked.connect(lambda: self.main_window.start_action("status"))
        self.run_btn.clicked.connect(lambda: self.main_window.start_action("run", dry_run=self.dry_run_box.isChecked()))
        verify_btn.clicked.connect(lambda: self.main_window.start_action("verify"))
        prune_btn.clicked.connect(lambda: self.main_window.start_action("prune", dry_run=self.dry_run_box.isChecked()))

        btn_row = QHBoxLayout()
        for b in (refresh_btn, self.run_btn, verify_btn, prune_btn):
            btn_row.addWidget(b)
        btn_row.addStretch(1)

        layout = QVBoxLayout(self)
        layout.addWidget(self.license_label)
        layout.addLayout(license_row)
        layout.addWidget(QLabel("Status"))
        layout.addWidget(self.status_view, stretch=1)
        layout.addWidget(self.dry_run_box)
        layout.addLayout(btn_row)

        self._license_allowed = True
        self.dry_run_box.toggled.connect(self._update_run_enabled)
        self.refresh_license_status()

    def refresh_license_status(self) -> None:
        access = licensing.check_access()
        self.license_label.setText(f"License: {access.reason}")
        self._license_allowed = access.allowed
        self._update_run_enabled()

    def _update_run_enabled(self) -> None:
        # A dry run never writes anything, so it stays available as a way to
        # evaluate the product even past the trial - only the real Run is gated.
        self.run_btn.setEnabled(self._license_allowed or self.dry_run_box.isChecked())

    def _activate_license(self) -> None:
        key = self.license_key_edit.text().strip()
        if not key:
            QMessageBox.warning(self, "No key", "Paste a license key first.")
            return
        try:
            info = licensing.save_license_key(key)
        except ValueError as e:
            QMessageBox.critical(self, "Activation failed", str(e))
            return
        QMessageBox.information(
            self, "Activated",
            f"Licensed to {info.customer} ({info.plan}/{info.billing}), expires {info.expires:%Y-%m-%d}.",
        )
        self.license_key_edit.clear()
        self.refresh_license_status()


# --------------------------------------------------------------------------
# Restore tab
# --------------------------------------------------------------------------

class RestoreTab(QWidget):
    def __init__(self, main_window: "MainWindow"):
        super().__init__()
        self.main_window = main_window

        self.pattern_edit = QLineEdit("*")
        self.dest_edit = QLineEdit()
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse)
        self.dry_run_box = QCheckBox("Dry run (list matches, restore nothing)")
        restore_btn = QPushButton("Restore")
        restore_btn.clicked.connect(self._restore)

        dest_row = QHBoxLayout()
        dest_row.addWidget(self.dest_edit)
        dest_row.addWidget(browse_btn)

        form = QFormLayout()
        form.addRow("Pattern (glob, e.g. *.pdf)", self.pattern_edit)
        form.addRow("Restore to folder", dest_row)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.dry_run_box)
        layout.addWidget(restore_btn)
        layout.addStretch(1)

    def _browse(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choose restore destination")
        if folder:
            self.dest_edit.setText(folder)

    def _restore(self) -> None:
        dest = self.dest_edit.text().strip()
        if not dest:
            QMessageBox.warning(self, "Missing destination", "Choose a folder to restore into first.")
            return
        self.main_window.start_action(
            "restore", dry_run=self.dry_run_box.isChecked(),
            dest_dir=Path(dest), pattern=self.pattern_edit.text().strip() or "*",
        )


# --------------------------------------------------------------------------
# Config tab
# --------------------------------------------------------------------------

class ConfigTab(QWidget):
    def __init__(self, main_window: "MainWindow"):
        super().__init__()
        self.main_window = main_window
        self.fields: dict[str, QWidget] = {}

        outer = QVBoxLayout(self)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        scroll.setWidget(inner)
        form_layout = QVBoxLayout(inner)

        form_layout.addWidget(self._build_source_group())
        form_layout.addWidget(self._build_local_group())
        form_layout.addWidget(self._build_s3_group())
        form_layout.addWidget(self._build_azure_group())
        form_layout.addWidget(self._build_release_group())
        form_layout.addWidget(self._build_retention_group())
        form_layout.addWidget(self._build_encryption_group())
        form_layout.addWidget(self._build_alerts_group())
        form_layout.addStretch(1)

        outer.addWidget(scroll, stretch=1)

        btn_row = QHBoxLayout()
        reload_btn = QPushButton("Reload from Disk")
        save_btn = QPushButton("Save Config")
        reload_btn.clicked.connect(self.reload)
        save_btn.clicked.connect(self.save)
        btn_row.addWidget(reload_btn)
        btn_row.addWidget(save_btn)
        btn_row.addStretch(1)
        outer.addLayout(btn_row)

        self.reload()

    # -- widget builders ----------------------------------------------

    def _line(self, key: str, form: QFormLayout, label: str, browse: str | None = None) -> None:
        edit = QLineEdit()
        self.fields[key] = edit
        if browse:
            row = QHBoxLayout()
            row.addWidget(edit)
            btn = QPushButton("Browse...")
            if browse == "dir":
                btn.clicked.connect(lambda: self._browse_dir(edit))
            else:
                btn.clicked.connect(lambda: self._browse_file(edit))
            row.addWidget(btn)
            form.addRow(label, row)
        else:
            form.addRow(label, edit)

    def _browse_dir(self, edit: QLineEdit) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choose folder")
        if folder:
            edit.setText(folder)

    def _browse_file(self, edit: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose file")
        if path:
            edit.setText(path)

    def _spin(self, key: str, form: QFormLayout, label: str, minimum: int, maximum: int) -> None:
        box = QSpinBox()
        box.setRange(minimum, maximum)
        self.fields[key] = box
        form.addRow(label, box)

    def _double_spin(self, key: str, form: QFormLayout, label: str, minimum: float, maximum: float, step: float) -> None:
        box = QDoubleSpinBox()
        box.setRange(minimum, maximum)
        box.setSingleStep(step)
        self.fields[key] = box
        form.addRow(label, box)

    def _check(self, key: str, form: QFormLayout, label: str) -> None:
        box = QCheckBox()
        self.fields[key] = box
        form.addRow(label, box)

    def _combo(self, key: str, form: QFormLayout, label: str, options: list[str]) -> None:
        box = QComboBox()
        box.addItems(options)
        self.fields[key] = box
        form.addRow(label, box)

    def _multiline(self, key: str, form: QFormLayout, label: str) -> None:
        edit = QPlainTextEdit()
        edit.setFixedHeight(70)
        self.fields[key] = edit
        form.addRow(label, edit)

    def _build_source_group(self) -> QGroupBox:
        box = QGroupBox("Source")
        form = QFormLayout(box)
        self._line("source_folder", form, "Source folder (blank = auto-detect Desktop)", browse="dir")
        self._line("source_folder_name", form, "Auto-detect folder name")
        self._combo("destination_type", form, "Destination type", ["local", "s3", "azure"])
        return box

    def _build_local_group(self) -> QGroupBox:
        box = QGroupBox("Destination - Local / SMB (used when destination_type = local)")
        form = QFormLayout(box)
        self._line("target_volume_label", form, "Volume label (preferred)")
        self._line("target_drive_letter", form, "Drive letter or UNC path (fallback)", browse="dir")
        self._line("backup_folder_name", form, "Backup folder name")
        return box

    def _build_s3_group(self) -> QGroupBox:
        box = QGroupBox("Destination - S3 (used when destination_type = s3)")
        form = QFormLayout(box)
        self._line("s3_bucket", form, "Bucket")
        self._line("s3_prefix", form, "Prefix")
        self._line("s3_region", form, "Region")
        self._line("s3_endpoint_url", form, "Endpoint URL (S3-compatible only, must be https://)")
        return box

    def _build_azure_group(self) -> QGroupBox:
        box = QGroupBox("Destination - Azure Blob (used when destination_type = azure)")
        form = QFormLayout(box)
        self._line("azure_container", form, "Container")
        self._line("azure_prefix", form, "Prefix")
        self._line("azure_connection_string_env", form, "Connection string env var name")
        return box

    def _build_release_group(self) -> QGroupBox:
        box = QGroupBox("Release & Versioning")
        form = QFormLayout(box)
        self._check("release_source", form, "Release source after verified copy")
        self._combo("release_mode", form, "Release mode", ["recycle", "quarantine", "keep"])
        self._line("quarantine_folder_name", form, "Quarantine folder name")
        self._check("versioning", form, "Keep prior versions instead of overwriting")
        return box

    def _build_retention_group(self) -> QGroupBox:
        box = QGroupBox("Retention, Filters & Timing")
        form = QFormLayout(box)
        self._spin("retention_days", form, "Retention days (0 = keep forever)", 0, 3650)
        self._spin("retention_min_versions", form, "Minimum versions to always keep", 0, 100)
        self._double_spin("min_free_space_margin", form, "Free space margin (local only)", 1.0, 3.0, 0.05)
        self._spin("check_interval_hours", form, "Check interval (hours, for watch/Task Scheduler)", 1, 168)
        self._spin("stability_seconds", form, "File stability wait (seconds)", 0, 300)
        self._multiline("exclude_patterns", form, "Exclude patterns (one glob per line)")
        self._multiline("include_patterns", form, "Include patterns (blank = include all not excluded)")
        return box

    def _build_encryption_group(self) -> QGroupBox:
        box = QGroupBox("Encryption")
        form = QFormLayout(box)
        self._combo("key_source", form, "Key source", ["env", "prompt", "keyfile", "dpapi"])
        self._line("key_env_var", form, "Key environment variable name")
        self._line("key_file", form, "Key file path (blank = default location)", browse="file")

        key_row = QHBoxLayout()
        self.new_key_edit = QLineEdit()
        self.new_key_edit.setReadOnly(True)
        self.new_key_edit.setPlaceholderText("Click Generate to create a new AES-256 key")
        gen_btn = QPushButton("Generate")
        set_env_btn = QPushButton("Set as My Environment Variable")
        gen_btn.clicked.connect(self._generate_key)
        set_env_btn.clicked.connect(self._set_env_key)
        key_row.addWidget(self.new_key_edit)
        key_row.addWidget(gen_btn)
        key_row.addWidget(set_env_btn)
        form.addRow("New key (env source)", key_row)

        init_btn = QPushButton("Initialize keyfile/dpapi key now")
        init_btn.clicked.connect(self._init_key_file)
        form.addRow("", init_btn)
        return box

    def _build_alerts_group(self) -> QGroupBox:
        box = QGroupBox("Alerts")
        form = QFormLayout(box)
        self._line("webhook_url", form, "Webhook URL (Slack/Teams/Zapier, optional)")
        self._spin("log_retention_months", form, "Audit log retention (months, 0 = forever)", 0, 120)
        self._line("hash_algorithm", form, "Hash algorithm")
        return box

    # -- key actions ------------------------------------------------------

    def _generate_key(self) -> None:
        key_b64 = base64.b64encode(crypto_utils.generate_random_key()).decode("ascii")
        self.new_key_edit.setText(key_b64)
        QMessageBox.information(
            self, "Key generated",
            "This key is shown once. Copy it somewhere safe now.\n\n"
            "Losing it makes every backup encrypted with it permanently unreadable.",
        )

    def _set_env_key(self) -> None:
        value = self.new_key_edit.text().strip()
        if not value:
            QMessageBox.warning(self, "No key", "Generate a key first.")
            return
        env_var = self.fields["key_env_var"].text().strip() or "BACKUP_ENCRYPTION_KEY"
        reply = QMessageBox.question(
            self, "Set environment variable",
            f"This permanently sets the '{env_var}' user environment variable on this machine "
            f"(via setx). Already-open terminals/programs won't see it until restarted. Continue?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            subprocess.run(["setx", env_var, value], check=True, capture_output=True, text=True)
            os.environ[env_var] = value
            QMessageBox.information(self, "Done", f"{env_var} set for your user account.")
        except Exception as e:
            QMessageBox.critical(self, "Failed", str(e))

    def _init_key_file(self) -> None:
        key_source = self.fields["key_source"].currentText()
        if key_source not in (crypto_utils.KeySource.KEYFILE, crypto_utils.KeySource.DPAPI):
            QMessageBox.information(self, "Not applicable", "Only used for key_source = keyfile or dpapi.")
            return
        key_file = self.fields["key_file"].text().strip() or None
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                crypto_utils.resolve_key(key_source, key_file=key_file)
            QMessageBox.information(self, "Key ready", buf.getvalue() or "Key initialized.")
        except Exception as e:
            QMessageBox.critical(self, "Failed", f"{buf.getvalue()}\n{e}")

    # -- load / save --------------------------------------------------

    def reload(self) -> None:
        data = load_config_dict(self.main_window.config_path)
        for key, widget in self.fields.items():
            value = data.get(key, DEFAULT_CONFIG.get(key))
            if isinstance(widget, QCheckBox):
                widget.setChecked(bool(value))
            elif isinstance(widget, QComboBox):
                idx = widget.findText(str(value))
                widget.setCurrentIndex(idx if idx >= 0 else 0)
            elif isinstance(widget, (QSpinBox, QDoubleSpinBox)):
                widget.setValue(value if value is not None else 0)
            elif isinstance(widget, QPlainTextEdit):
                widget.setPlainText("\n".join(value or []))
            else:
                widget.setText("" if value is None else str(value))

    def save(self) -> None:
        data = dict(DEFAULT_CONFIG)
        for key, widget in self.fields.items():
            if isinstance(widget, QCheckBox):
                data[key] = widget.isChecked()
            elif isinstance(widget, QComboBox):
                data[key] = widget.currentText()
            elif isinstance(widget, QSpinBox):
                data[key] = widget.value()
            elif isinstance(widget, QDoubleSpinBox):
                data[key] = round(widget.value(), 3)
            elif isinstance(widget, QPlainTextEdit):
                data[key] = [line for line in widget.toPlainText().splitlines() if line.strip()]
            else:
                data[key] = widget.text()
        self.main_window.config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        QMessageBox.information(self, "Saved", f"Config written to {self.main_window.config_path}")


# --------------------------------------------------------------------------
# Scheduling tab
# --------------------------------------------------------------------------

class SchedulingTab(QWidget):
    TASK_NAME = "SentinelBackup"

    def __init__(self, main_window: "MainWindow"):
        super().__init__()
        self.main_window = main_window

        self.interval_box = QSpinBox()
        self.interval_box.setRange(1, 168)
        self.interval_box.setValue(6)

        query_btn = QPushButton("Check Task Status")
        install_btn = QPushButton("Install / Update Scheduled Task")
        run_now_btn = QPushButton("Run Task Now")
        uninstall_btn = QPushButton("Uninstall Scheduled Task")

        query_btn.clicked.connect(self._query)
        install_btn.clicked.connect(self._install)
        run_now_btn.clicked.connect(self._run_now)
        uninstall_btn.clicked.connect(self._uninstall)

        form = QFormLayout()
        form.addRow("Interval (hours)", self.interval_box)

        btn_row = QHBoxLayout()
        for b in (query_btn, install_btn, run_now_btn, uninstall_btn):
            btn_row.addWidget(b)

        note = QLabel(
            "Registers a per-user Scheduled Task that survives reboot and catches up on wake.\n"
            "If installation fails with an access-denied error, re-launch this GUI as Administrator."
        )
        note.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(btn_row)
        layout.addWidget(note)
        layout.addStretch(1)

    def _query(self) -> None:
        self.main_window.start_process([
            "powershell.exe", "-NoProfile", "-Command",
            f"Get-ScheduledTask -TaskName '{self.TASK_NAME}' -ErrorAction SilentlyContinue | "
            f"Format-List TaskName, State; "
            f"if (-not (Get-ScheduledTask -TaskName '{self.TASK_NAME}' -ErrorAction SilentlyContinue)) "
            f"{{ Write-Output 'Not installed.' }}",
        ])

    def _install(self) -> None:
        if not INSTALL_SCRIPT_PATH.exists():
            QMessageBox.critical(self, "Missing script", f"{INSTALL_SCRIPT_PATH} not found.")
            return
        self.main_window.start_process([
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(INSTALL_SCRIPT_PATH), "-IntervalHours", str(self.interval_box.value()),
        ])

    def _run_now(self) -> None:
        self.main_window.start_process([
            "powershell.exe", "-NoProfile", "-Command", f"Start-ScheduledTask -TaskName '{self.TASK_NAME}'",
        ])

    def _uninstall(self) -> None:
        reply = QMessageBox.question(
            self, "Uninstall scheduled task",
            f"This removes the '{self.TASK_NAME}' Scheduled Task. Backups will no longer run "
            f"automatically. Your existing encrypted backups are not affected. Continue?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self.main_window.start_process([
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(INSTALL_SCRIPT_PATH), "-Uninstall",
        ])


# --------------------------------------------------------------------------
# Main window
# --------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self, config_path: Path):
        super().__init__()
        self.config_path = config_path
        self.setWindowTitle("Sentinel Backup")
        self.resize(900, 720)

        self._thread: QThread | None = None
        self._worker: QObject | None = None
        self._current_action: str | None = None

        self.dashboard_tab = DashboardTab(self)
        self.restore_tab = RestoreTab(self)
        self.config_tab = ConfigTab(self)
        self.scheduling_tab = SchedulingTab(self)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.restore_tab, "Restore")
        self.tabs.addTab(self.config_tab, "Config")
        self.tabs.addTab(self.scheduling_tab, "Scheduling")

        self.log_view = QPlainTextEdit(readOnly=True)
        self.log_view.setFont(MONOSPACE)
        self.log_view.setPlaceholderText("Activity log")

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.tabs)
        splitter.addWidget(self.log_view)
        splitter.setSizes([500, 200])

        self.setCentralWidget(splitter)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Idle")

        self.start_action("status")

    # -- busy / thread management -------------------------------------

    def _busy(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    def _set_running(self, label: str) -> None:
        self.statusBar().showMessage(f"Running: {label}...")
        self.tabs.setEnabled(False)

    def start_action(self, action: str, dry_run: bool = False, **kwargs) -> None:
        if self._busy():
            QMessageBox.warning(self, "Busy", "Another operation is already running. Please wait.")
            return
        if action == "status":
            self.dashboard_tab.status_view.clear()
        else:
            self.log_view.clear()
        self._current_action = action
        self._set_running(action)

        self._thread = QThread()
        self._worker = EngineWorker(self.config_path, action, dry_run=dry_run, **kwargs)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.log_line.connect(self._on_log_line)
        self._worker.finished.connect(self._on_finished)
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def start_process(self, args: list[str]) -> None:
        if self._busy():
            QMessageBox.warning(self, "Busy", "Another operation is already running. Please wait.")
            return
        self.log_view.clear()
        self._current_action = "process"
        self._set_running("scheduled task command")

        self._thread = QThread()
        self._worker = ProcessWorker(args)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.log_line.connect(self._on_log_line)
        self._worker.finished.connect(self._on_finished)
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _on_log_line(self, line: str) -> None:
        if self._current_action == "status":
            self.dashboard_tab.status_view.appendPlainText(line)
        else:
            self.log_view.appendPlainText(line)

    def _on_finished(self, code: int) -> None:
        self.tabs.setEnabled(True)
        self.statusBar().showMessage(f"Idle (last exit code: {code})")
        self._current_action = None
        self.dashboard_tab.refresh_license_status()


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow(DEFAULT_CONFIG_PATH)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
