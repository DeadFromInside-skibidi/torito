"""
torito.gui — Windows 10 Native Tkinter GUI
=============================================
Classic Windows 10 dialog-box style interface using ``ttk`` with the
``vista`` theme, ``#F0F0F0`` system surfaces, Win32 group frames,
directory browse dialogs, a threaded non-blocking build controller,
a determinate stage progress bar, and a real-time scrolling
stdout/stderr telemetry console.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from .builder import (
    STAGE_LABELS,
    TOTAL_STAGES,
    BuildController,
    BuildResult,
    BuildStage,
)


# ──────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────
BG_COLOUR = "#F0F0F0"
CONSOLE_BG = "#1E1E1E"
CONSOLE_FG = "#CCCCCC"
CONSOLE_FONT = ("Consolas", 9)
LABEL_FONT = ("Segoe UI", 9)
TITLE_FONT = ("Segoe UI", 11, "bold")
WINDOW_WIDTH = 780
WINDOW_HEIGHT = 620
POLL_INTERVAL_MS = 50


class ToritoApp:
    """
    The main application window.

    All GUI updates happen on the Tk main thread via a polling queue
    so that the background build thread never touches Tk widgets directly.
    """

    def __init__(self) -> None:
        self._root = tk.Tk()
        self._root.title("Torito — Linux ISO Compiler")
        self._root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self._root.minsize(640, 480)
        self._root.configure(bg=BG_COLOUR)
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Apply the native Vista theme for Win32-style controls
        style = ttk.Style(self._root)
        available_themes = style.theme_names()
        if "vista" in available_themes:
            style.theme_use("vista")
        elif "winnative" in available_themes:
            style.theme_use("winnative")
        elif "clam" in available_themes:
            style.theme_use("clam")

        # Custom styles
        style.configure("TLabel", background=BG_COLOUR, font=LABEL_FONT)
        style.configure("TButton", font=LABEL_FONT)
        style.configure("Title.TLabel", background=BG_COLOUR, font=TITLE_FONT)
        style.configure("Status.TLabel", background=BG_COLOUR, font=("Segoe UI", 9, "italic"))
        style.configure(
            "Console.TFrame",
            background=CONSOLE_BG,
        )

        # Thread-safe message queue for GUI updates
        self._gui_queue: queue.Queue = queue.Queue()

        # Build controller
        self._controller = BuildController()
        self._controller.on_stage_changed = self._on_stage_changed
        self._controller.on_progress = self._on_progress
        self._controller.on_log = self._on_log
        self._controller.on_finished = self._on_finished

        # Tk variables
        self._manifest_var = tk.StringVar(value="")
        self._stage_var = tk.StringVar(value="Ready")
        self._progress_var = tk.DoubleVar(value=0.0)

        self._build_widgets()
        self._poll_gui_queue()

    # ──────────────────────────────────────────────────────────────
    # Widget construction
    # ──────────────────────────────────────────────────────────────

    def _build_widgets(self) -> None:
        """Construct the entire window layout."""
        main_frame = ttk.Frame(self._root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # ── Title ──
        ttk.Label(
            main_frame,
            text="Torito — Rootless Linux ISO Compiler",
            style="Title.TLabel",
        ).pack(anchor=tk.W, pady=(0, 8))

        # ── Manifest selection group ──
        manifest_group = ttk.LabelFrame(
            main_frame,
            text=" Build Manifest ",
            padding=10,
        )
        manifest_group.pack(fill=tk.X, pady=(0, 8))

        manifest_row = ttk.Frame(manifest_group)
        manifest_row.pack(fill=tk.X)

        ttk.Label(manifest_row, text="Config file:").pack(side=tk.LEFT, padx=(0, 6))

        self._manifest_entry = ttk.Entry(
            manifest_row,
            textvariable=self._manifest_var,
            width=60,
        )
        self._manifest_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self._browse_btn = ttk.Button(
            manifest_row,
            text="Browse…",
            width=10,
            command=self._browse_manifest,
        )
        self._browse_btn.pack(side=tk.LEFT)

        # Supported formats hint
        ttk.Label(
            manifest_group,
            text="Supported formats: TOML (.toml), JSON (.json), INI (.ini / .conf)",
            foreground="#666666",
        ).pack(anchor=tk.W, pady=(4, 0))

        # ── Build controls group ──
        controls_group = ttk.LabelFrame(
            main_frame,
            text=" Build Controls ",
            padding=10,
        )
        controls_group.pack(fill=tk.X, pady=(0, 8))

        controls_row = ttk.Frame(controls_group)
        controls_row.pack(fill=tk.X)

        self._build_btn = ttk.Button(
            controls_row,
            text="▶  Build ISO",
            width=16,
            command=self._start_build,
        )
        self._build_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._cancel_btn = ttk.Button(
            controls_row,
            text="■  Cancel",
            width=12,
            command=self._cancel_build,
            state=tk.DISABLED,
        )
        self._cancel_btn.pack(side=tk.LEFT, padx=(0, 16))

        # Stage label
        self._stage_label = ttk.Label(
            controls_row,
            textvariable=self._stage_var,
            style="Status.TLabel",
        )
        self._stage_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # ── Progress bar ──
        progress_frame = ttk.Frame(controls_group)
        progress_frame.pack(fill=tk.X, pady=(8, 0))

        self._progress_bar = ttk.Progressbar(
            progress_frame,
            orient=tk.HORIZONTAL,
            mode="determinate",
            variable=self._progress_var,
            maximum=100.0,
        )
        self._progress_bar.pack(fill=tk.X)

        # ── Telemetry console ──
        console_group = ttk.LabelFrame(
            main_frame,
            text=" Build Telemetry ",
            padding=4,
        )
        console_group.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        console_frame = ttk.Frame(console_group)
        console_frame.pack(fill=tk.BOTH, expand=True)

        self._console_text = tk.Text(
            console_frame,
            bg=CONSOLE_BG,
            fg=CONSOLE_FG,
            font=CONSOLE_FONT,
            wrap=tk.WORD,
            state=tk.DISABLED,
            borderwidth=1,
            relief=tk.SUNKEN,
            padx=6,
            pady=4,
            insertbackground=CONSOLE_FG,
            selectbackground="#264F78",
            selectforeground="#FFFFFF",
        )
        self._console_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        console_scroll = ttk.Scrollbar(
            console_frame,
            orient=tk.VERTICAL,
            command=self._console_text.yview,
        )
        console_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._console_text.configure(yscrollcommand=console_scroll.set)

        # Configure text tags for coloured output
        self._console_text.tag_configure("info", foreground="#CCCCCC")
        self._console_text.tag_configure("stage", foreground="#569CD6")
        self._console_text.tag_configure("warn", foreground="#CE9178")
        self._console_text.tag_configure("error", foreground="#F44747")
        self._console_text.tag_configure("success", foreground="#6A9955")

        # ── Status bar ──
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X)

        self._status_label = ttk.Label(
            status_frame,
            text="Ready — select a build manifest to begin",
            foreground="#666666",
        )
        self._status_label.pack(side=tk.LEFT)

        self._version_label = ttk.Label(
            status_frame,
            text="Torito v1.0.0",
            foreground="#999999",
        )
        self._version_label.pack(side=tk.RIGHT)

    # ──────────────────────────────────────────────────────────────
    # GUI actions
    # ──────────────────────────────────────────────────────────────

    def _browse_manifest(self) -> None:
        """Open a file dialog to select a build manifest."""
        filetypes = [
            ("All supported", "*.toml *.json *.ini *.conf *.cfg"),
            ("TOML files", "*.toml"),
            ("JSON files", "*.json"),
            ("INI / Conf files", "*.ini *.conf *.cfg"),
            ("All files", "*.*"),
        ]
        path = filedialog.askopenfilename(
            title="Select Build Manifest",
            filetypes=filetypes,
            parent=self._root,
        )
        if path:
            self._manifest_var.set(path)
            self._status_label.configure(text=f"Manifest: {os.path.basename(path)}")

    def _start_build(self) -> None:
        """Validate inputs and launch the build in a background thread."""
        manifest = self._manifest_var.get().strip()
        if not manifest:
            messagebox.showwarning(
                "No Manifest",
                "Please select a build manifest file first.",
                parent=self._root,
            )
            return

        if not os.path.isfile(manifest):
            messagebox.showerror(
                "File Not Found",
                f"The manifest file does not exist:\n{manifest}",
                parent=self._root,
            )
            return

        # Clear console
        self._console_text.configure(state=tk.NORMAL)
        self._console_text.delete("1.0", tk.END)
        self._console_text.configure(state=tk.DISABLED)

        # Update button states
        self._build_btn.configure(state=tk.DISABLED)
        self._cancel_btn.configure(state=tk.NORMAL)
        self._browse_btn.configure(state=tk.DISABLED)
        self._manifest_entry.configure(state=tk.DISABLED)
        self._progress_var.set(0.0)

        self._append_console(f"Starting build with manifest: {manifest}\n", "info")
        self._append_console("─" * 60 + "\n", "info")

        try:
            self._controller.start(manifest)
        except RuntimeError as exc:
            messagebox.showerror("Build Error", str(exc), parent=self._root)
            self._reset_ui()

    def _cancel_build(self) -> None:
        """Signal the build thread to cancel."""
        if self._controller.is_running:
            result = messagebox.askyesno(
                "Cancel Build",
                "Are you sure you want to cancel the current build?",
                parent=self._root,
            )
            if result:
                self._controller.cancel()
                self._cancel_btn.configure(state=tk.DISABLED)

    def _on_close(self) -> None:
        """Handle window close — cancel any running build first."""
        if self._controller.is_running:
            self._controller.cancel()
        self._root.destroy()

    # ──────────────────────────────────────────────────────────────
    # Thread-safe callbacks (enqueue updates for the main thread)
    # ──────────────────────────────────────────────────────────────

    def _on_stage_changed(self, stage: BuildStage, label: str) -> None:
        self._gui_queue.put(("stage", stage, label))

    def _on_progress(self, value: float) -> None:
        self._gui_queue.put(("progress", value))

    def _on_log(self, message: str) -> None:
        self._gui_queue.put(("log", message))

    def _on_finished(self, result: BuildResult) -> None:
        self._gui_queue.put(("finished", result))

    # ──────────────────────────────────────────────────────────────
    # Main-thread GUI queue consumer
    # ──────────────────────────────────────────────────────────────

    def _poll_gui_queue(self) -> None:
        """Drain the queue and apply updates on the Tk main thread."""
        try:
            while True:
                msg = self._gui_queue.get_nowait()
                kind = msg[0]

                if kind == "stage":
                    stage: BuildStage = msg[1]
                    label: str = msg[2]
                    self._stage_var.set(label)
                    self._status_label.configure(text=label)

                elif kind == "progress":
                    val: float = msg[1]
                    self._progress_var.set(val * 100.0)

                elif kind == "log":
                    text: str = msg[1]
                    tag = "info"
                    if text.startswith("[stage]"):
                        tag = "stage"
                    elif "⚠" in text or "WARNING" in text.upper():
                        tag = "warn"
                    elif "✗" in text or "ERROR" in text.upper():
                        tag = "error"
                    elif "✓" in text or "complete" in text.lower():
                        tag = "success"
                    self._append_console(text + "\n", tag)

                elif kind == "finished":
                    result: BuildResult = msg[1]
                    self._on_build_finished(result)

        except queue.Empty:
            pass

        # Schedule next poll
        self._root.after(POLL_INTERVAL_MS, self._poll_gui_queue)

    def _append_console(self, text: str, tag: str = "info") -> None:
        """Append text to the console widget and auto-scroll."""
        self._console_text.configure(state=tk.NORMAL)
        self._console_text.insert(tk.END, text, tag)
        self._console_text.see(tk.END)
        self._console_text.configure(state=tk.DISABLED)

    def _on_build_finished(self, result: BuildResult) -> None:
        """Handle build completion on the main thread."""
        self._append_console("─" * 60 + "\n", "info")

        if result.success:
            self._progress_var.set(100.0)
            size_mb = result.output_size / (1024 * 1024)
            self._append_console(
                f"✓ Build succeeded in {result.elapsed_seconds:.2f}s\n",
                "success",
            )
            self._append_console(
                f"  Output: {result.output_path} ({size_mb:.1f} MB)\n",
                "success",
            )
            self._append_console(
                f"  VFS nodes: {result.node_count:,}\n",
                "success",
            )
            self._status_label.configure(
                text=f"✓ Build complete — {size_mb:.1f} MB in {result.elapsed_seconds:.1f}s"
            )
            messagebox.showinfo(
                "Build Complete",
                f"ISO image built successfully!\n\n"
                f"Output: {result.output_path}\n"
                f"Size: {size_mb:.1f} MB\n"
                f"Time: {result.elapsed_seconds:.2f}s\n"
                f"VFS Nodes: {result.node_count:,}",
                parent=self._root,
            )
        else:
            self._append_console(
                f"✗ Build failed: {result.error_message}\n",
                "error",
            )
            self._status_label.configure(text=f"✗ Build failed — {result.error_message}")
            messagebox.showerror(
                "Build Failed",
                f"The build encountered an error:\n\n{result.error_message}",
                parent=self._root,
            )

        self._reset_ui()

    def _reset_ui(self) -> None:
        """Re-enable input controls after a build completes or fails."""
        self._build_btn.configure(state=tk.NORMAL)
        self._cancel_btn.configure(state=tk.DISABLED)
        self._browse_btn.configure(state=tk.NORMAL)
        self._manifest_entry.configure(state=tk.NORMAL)

    # ──────────────────────────────────────────────────────────────
    # Application lifecycle
    # ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Start the Tk main loop."""
        # Centre the window on screen
        self._root.update_idletasks()
        sw = self._root.winfo_screenwidth()
        sh = self._root.winfo_screenheight()
        x = (sw - WINDOW_WIDTH) // 2
        y = (sh - WINDOW_HEIGHT) // 2
        self._root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{x}+{y}")

        self._root.mainloop()


def main() -> None:
    """Entry point for the GUI application."""
    app = ToritoApp()
    app.run()

