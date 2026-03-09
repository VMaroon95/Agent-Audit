"""
File System Watcher — Real-time monitoring of agent file operations.

Uses polling-based observation to detect file changes in monitored
directories and automatically feeds them into the audit engine.
"""

import os
import time
import hashlib
from pathlib import Path
from typing import Callable, Optional


class FileWatcher:
    """
    Monitors directories for file changes and reports them to a callback.

    Designed for lightweight, cross-platform operation without inotify
    dependencies. Suitable for sandboxed environments.
    """

    def __init__(self, watch_dirs: list[str], callback: Callable, interval: float = 1.0):
        self.watch_dirs = [Path(d) for d in watch_dirs]
        self.callback = callback
        self.interval = interval
        self._baseline: dict[str, tuple[float, int, str]] = {}
        self._running = False

    def snapshot(self) -> dict[str, tuple[float, int, str]]:
        """Capture current state of all watched files."""
        state = {}
        for watch_dir in self.watch_dirs:
            if not watch_dir.exists():
                continue
            for path in watch_dir.rglob("*"):
                if path.is_file():
                    try:
                        stat = path.stat()
                        key = str(path)
                        content_hash = self._quick_hash(path)
                        state[key] = (stat.st_mtime, stat.st_size, content_hash)
                    except (OSError, PermissionError):
                        continue
        return state

    def detect_changes(self) -> list[dict]:
        """Compare current state against baseline and return changes."""
        current = self.snapshot()
        changes = []

        # New or modified files
        for path, (mtime, size, chash) in current.items():
            if path not in self._baseline:
                changes.append({
                    "type": "file_write",
                    "target": path,
                    "metadata": {"size": size, "event": "created"},
                })
            else:
                old_mtime, old_size, old_hash = self._baseline[path]
                if chash != old_hash:
                    changes.append({
                        "type": "file_write",
                        "target": path,
                        "metadata": {
                            "size": size,
                            "old_size": old_size,
                            "event": "modified",
                        },
                    })

        # Deleted files
        for path in self._baseline:
            if path not in current:
                changes.append({
                    "type": "file_delete",
                    "target": path,
                    "metadata": {"event": "deleted"},
                })

        self._baseline = current
        return changes

    def start(self):
        """Start polling loop (blocking)."""
        self._baseline = self.snapshot()
        self._running = True
        while self._running:
            time.sleep(self.interval)
            changes = self.detect_changes()
            for change in changes:
                self.callback(change)

    def stop(self):
        """Stop the polling loop."""
        self._running = False

    @staticmethod
    def _quick_hash(path: Path, chunk_size: int = 8192) -> str:
        """Fast hash of file contents for change detection."""
        h = hashlib.md5()
        try:
            with open(path, "rb") as f:
                chunk = f.read(chunk_size)
                while chunk:
                    h.update(chunk)
                    chunk = f.read(chunk_size)
        except (OSError, PermissionError):
            return ""
        return h.hexdigest()
