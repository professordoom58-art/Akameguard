"""Small, read-only Tkinter front end for the AkameGuard scanner.

Tkinter is intentionally imported only by :func:`launch_gui` so importing the
package and running the command-line scanner do not require a display.
"""

from dataclasses import dataclass
import queue
from pathlib import Path
import threading
from typing import Callable, Optional, Sequence, Tuple, cast

from .__main__ import _text_report
from .config import ConfigError, ScanConfig, load_config
from .rules import Rule, RuleError, load_rules
from .scanner import (
    ScanError,
    ScanResult,
    _iter_candidate_files,
    scan_files,
    scan_root,
)


SEVERITIES = ("low", "medium", "high")
SEVERITY_COLORS = {
    "critical": "#b00020",
    "high": "#b00020",
    "medium": "#9a6700",
    "low": "#666666",
}


@dataclass(frozen=True)
class ScanMessage:
    kind: str
    payload: object = None


def is_path_inside(path: Path, folder: Path) -> bool:
    """Return whether *path* is the folder itself or below it."""

    try:
        path.resolve().relative_to(folder.resolve())
    except ValueError:
        return False
    return True


def format_scan_log(
    result: ScanResult,
    folder: str,
    min_severity: str,
    show_full_list: bool = False,
) -> str:
    """Format the GUI log using the CLI's grouped or verbose report format."""

    lines = [
        "Scan started: %s" % Path(folder).expanduser().resolve(),
        "Minimum severity: %s" % min_severity,
        "",
        _text_report(result, verbose=show_full_list),
    ]
    return "\n".join(lines)


def _scan_with_cancellation(
    folder: str,
    config: ScanConfig,
    rules: Sequence[Rule],
    min_severity: str,
    cancel_event: threading.Event,
) -> Optional[ScanResult]:
    """Scan one file at a time so cancellation is checked between files."""

    target = Path(folder).expanduser().resolve()
    root = scan_root(str(target))
    findings = []
    skipped = []
    for path in _iter_candidate_files(target, config.ignore_folders):
        if cancel_event.is_set():
            return None
        partial = scan_files((path,), root, config, rules, min_severity=min_severity)
        findings.extend(partial.findings)
        skipped.extend(partial.skipped_files)
    if cancel_event.is_set():
        return None
    return ScanResult(findings=tuple(findings), skipped_files=tuple(skipped))


def _run_scan_worker(
    folder: str,
    min_severity: str,
    messages,
    cancel_event: threading.Event,
    scan_func: Optional[Callable] = None,
    config_loader: Optional[Callable[[], ScanConfig]] = None,
    rules_loader: Optional[Callable[[Tuple[Path, ...]], Sequence[Rule]]] = None,
) -> None:
    """Run scanner work off the Tk main thread and send only queue messages."""

    try:
        target = Path(folder).expanduser().resolve()
        if not target.is_dir():
            raise ScanError("scan folder is not a directory: %s" % target)
        if cancel_event.is_set():
            messages.put(ScanMessage("cancelled"))
            return
        config_loader = config_loader or load_config
        rules_loader = rules_loader or load_rules
        config = config_loader()
        rules = rules_loader(config.rule_paths)
        if scan_func is None:
            result = _scan_with_cancellation(
                str(target), config, rules, min_severity, cancel_event
            )
        else:
            result = scan_func(str(target), config, rules, min_severity)
            if cancel_event.is_set():
                result = None
        if result is None:
            messages.put(ScanMessage("cancelled"))
        else:
            messages.put(ScanMessage("done", result))
    except (ConfigError, RuleError, ScanError, OSError, ValueError) as exc:
        messages.put(ScanMessage("error", str(exc)))
    except Exception as exc:  # Keep GUI failures visible instead of crashing the window.
        messages.put(ScanMessage("error", "%s: %s" % (type(exc).__name__, exc)))


def start_scan_worker(
    folder: str,
    min_severity: str,
    messages,
    cancel_event: Optional[threading.Event] = None,
    scan_func: Optional[Callable] = None,
    config_loader: Optional[Callable[[], ScanConfig]] = None,
    rules_loader: Optional[Callable[[Tuple[Path, ...]], Sequence[Rule]]] = None,
):
    """Start a scanner worker and return ``(thread, cancel_event)``."""

    cancel_event = cancel_event or threading.Event()
    thread = threading.Thread(
        target=_run_scan_worker,
        args=(
            folder,
            min_severity,
            messages,
            cancel_event,
            scan_func,
            config_loader,
            rules_loader,
        ),
        name="akameguard-scan",
        daemon=True,
    )
    thread.start()
    return thread, cancel_event


class AkameGuardGui:
    """Tk widgets and main-thread event handling for the read-only GUI."""

    def __init__(self, root, tk_module, ttk_module, filedialog_module, messagebox_module):
        self.root = root
        self.tk = tk_module
        self.ttk = ttk_module
        self.filedialog = filedialog_module
        self.messagebox = messagebox_module
        self.messages = queue.Queue()
        self.thread = None
        self.cancel_event = None
        self.scan_folder = None
        self.scan_min_severity = "medium"
        self.last_result = None
        self.start_line = ""
        self.poll_after = None

        root.title("AkameGuard")
        root.geometry("860x620")
        root.minsize(640, 420)
        root.protocol("WM_DELETE_WINDOW", self._close)

        self.folder = tk_module.StringVar()
        self.severity = tk_module.StringVar(value="medium")
        self.show_full_list = tk_module.BooleanVar(value=False)
        self.status = tk_module.StringVar(value="Idle")

        self._build_widgets()

    def _build_widgets(self):
        top = self.ttk.Frame(self.root, padding=8)
        top.grid(row=0, column=0, sticky="ew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        top.columnconfigure(1, weight=1)

        self.ttk.Label(top, text="Folder:").grid(row=0, column=0, padx=(0, 6), sticky="w")
        self.folder_entry = self.ttk.Entry(top, textvariable=self.folder)
        self.folder_entry.grid(row=0, column=1, sticky="ew")
        self.browse_button = self.ttk.Button(top, text="Browse", command=self._browse)
        self.browse_button.grid(row=0, column=2, padx=(6, 0))

        controls = self.ttk.Frame(top)
        controls.grid(row=1, column=0, columnspan=3, pady=(8, 0), sticky="w")
        self.run_button = self.ttk.Button(controls, text="Run scan", command=self._run_scan)
        self.run_button.grid(row=0, column=0, padx=(0, 6))
        self.cancel_button = self.ttk.Button(
            controls, text="Cancel", command=self._cancel_scan, state="disabled"
        )
        self.cancel_button.grid(row=0, column=1, padx=(0, 12))
        self.ttk.Label(controls, text="Minimum severity:").grid(row=0, column=2, padx=(0, 4))
        self.severity_box = self.ttk.Combobox(
            controls,
            textvariable=self.severity,
            values=SEVERITIES,
            state="readonly",
            width=9,
        )
        self.severity_box.grid(row=0, column=3, padx=(0, 12))
        self.ttk.Checkbutton(
            controls,
            text="Show full list",
            variable=self.show_full_list,
            command=self._show_full_list_changed,
        ).grid(row=0, column=4)

        log_frame = self.ttk.Frame(self.root, padding=(8, 0, 8, 0))
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log = self.tk.Text(log_frame, wrap="none", state="disabled", undo=False)
        self.log.grid(row=0, column=0, sticky="nsew")
        scrollbar = self.ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scrollbar.set)
        for severity, color in SEVERITY_COLORS.items():
            self.log.tag_configure(severity, foreground=color)

        bottom = self.ttk.Frame(self.root, padding=8)
        bottom.grid(row=2, column=0, sticky="ew")
        bottom.columnconfigure(0, weight=1)
        self.ttk.Label(bottom, textvariable=self.status).grid(row=0, column=0, sticky="w")
        self.ttk.Button(bottom, text="Copy log", command=self._copy_log).grid(
            row=0, column=1, padx=(6, 0)
        )
        self.ttk.Button(bottom, text="Save log", command=self._save_log).grid(
            row=0, column=2, padx=(6, 0)
        )

    def _browse(self):
        selected = self.filedialog.askdirectory(title="Choose a folder to scan")
        if selected:
            self.folder.set(selected)

    def _set_log(self, text):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.insert("1.0", text)
        self._tag_severities(text)
        self.log.configure(state="disabled")
        self.log.see("end")

    def _tag_severities(self, text):
        import re

        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in re.finditer(r"\b(critical|high|medium|low)\b", line, re.IGNORECASE):
                severity = match.group(1).lower()
                start = "%d.%d" % (line_number, match.start(1))
                end = "%d.%d" % (line_number, match.end(1))
                self.log.tag_add(severity, start, end)

    def _run_scan(self):
        if self.thread is not None and self.thread.is_alive():
            return
        raw_folder = self.folder.get().strip()
        folder = Path(raw_folder).expanduser().resolve() if raw_folder else None
        if folder is None or not folder.is_dir():
            message = "Choose an existing folder before running a scan."
            self._set_log("Error: %s" % message)
            self.status.set("Idle")
            self.messagebox.showerror("AkameGuard", message)
            return

        self.scan_folder = folder
        self.scan_min_severity = self.severity.get()
        self.last_result = None
        self.start_line = "Scan started: %s\nMinimum severity: %s" % (
            folder,
            self.scan_min_severity,
        )
        self._set_log(self.start_line)
        self.status.set("Scanning")
        self.run_button.configure(state="disabled")
        self.browse_button.configure(state="disabled")
        self.severity_box.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.messages = queue.Queue()
        self.thread, self.cancel_event = start_scan_worker(
            str(folder), self.severity.get(), self.messages
        )
        self.poll_after = self.root.after(50, self._poll_messages)

    def _poll_messages(self):
        try:
            while True:
                message = self.messages.get_nowait()
                self._handle_message(message)
        except queue.Empty:
            pass
        if self.thread is not None and self.thread.is_alive():
            self.poll_after = self.root.after(50, self._poll_messages)
        elif self.thread is not None:
            self._finish_controls()

    def _handle_message(self, message: ScanMessage):
        if message.kind == "done":
            self.last_result = cast(ScanResult, message.payload)
            self._set_log(
                format_scan_log(
                    self.last_result,
                    str(self.scan_folder),
                    self.scan_min_severity,
                    self.show_full_list.get(),
                )
            )
            self.status.set("Done: %d findings" % len(self.last_result.findings))
        elif message.kind == "cancelled":
            self._set_log(self.start_line + "\n\nScan cancelled.")
            self.status.set("Idle")
        elif message.kind == "error":
            error = "Scan error: %s" % message.payload
            self._set_log(self.start_line + "\n\n" + error)
            self.status.set("Idle")
            self.messagebox.showerror("AkameGuard", str(message.payload))

    def _finish_controls(self):
        self.run_button.configure(state="normal")
        self.browse_button.configure(state="normal")
        self.severity_box.configure(state="readonly")
        self.cancel_button.configure(state="disabled")

    def _cancel_scan(self):
        if self.cancel_event is not None and self.thread is not None and self.thread.is_alive():
            self.cancel_event.set()
            self.cancel_button.configure(state="disabled")
            self._set_log(self.start_line + "\n\nCancellation requested.")

    def _show_full_list_changed(self):
        if self.last_result is not None and self.scan_folder is not None:
            self._set_log(
                format_scan_log(
                    self.last_result,
                    str(self.scan_folder),
                    self.scan_min_severity,
                    self.show_full_list.get(),
                )
            )

    def _copy_log(self):
        try:
            text = self.log.get("1.0", "end-1c")
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
        except self.tk.TclError as exc:
            self.messagebox.showerror("AkameGuard", "Could not copy the log: %s" % exc)

    def _save_log(self):
        filename = self.filedialog.asksaveasfilename(
            title="Save AkameGuard log",
            defaultextension=".txt",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
        )
        if not filename:
            return
        output = Path(filename).expanduser().resolve()
        if self.scan_folder is not None and is_path_inside(output, self.scan_folder):
            self.messagebox.showerror(
                "AkameGuard",
                "Refusing to save the log inside the scanned folder.",
            )
            return
        try:
            output.write_text(self.log.get("1.0", "end-1c") + "\n", encoding="utf-8")
        except OSError as exc:
            self.messagebox.showerror("AkameGuard", "Could not save the log: %s" % exc)

    def _close(self):
        if self.cancel_event is not None:
            self.cancel_event.set()
        self.root.destroy()


def launch_gui() -> int:
    """Import Tkinter lazily, open the GUI, and return a CLI-style status."""

    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError as exc:
        print("Error: Tkinter is required for the GUI: %s" % exc)
        return 2
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print("Error: could not open the AkameGuard GUI: %s" % exc)
        return 2
    try:
        AkameGuardGui(root, tk, ttk, filedialog, messagebox)
        root.mainloop()
    except tk.TclError as exc:
        print("Error: the AkameGuard GUI stopped unexpectedly: %s" % exc)
        return 2
    except Exception as exc:
        print("Error: the AkameGuard GUI stopped unexpectedly: %s: %s" % (type(exc).__name__, exc))
        return 2
    return 0
