"""Capture and analysis history tracking."""

import time
from dataclasses import dataclass
from threading import Lock


@dataclass
class HistoryEntry:
    tool_name: str
    file_path: str
    timestamp: float
    summary: str
    duration: float = 0.0


class CaptureHistory:
    """Thread-safe capture/analysis history."""

    MAX_ENTRIES = 100

    def __init__(self) -> None:
        self._entries: list[HistoryEntry] = []
        self._lock = Lock()

    def add(self, tool_name: str, file_path: str, summary: str, duration: float = 0.0) -> None:
        with self._lock:
            entry = HistoryEntry(
                tool_name=tool_name,
                file_path=file_path,
                timestamp=time.time(),
                summary=summary,
                duration=duration,
            )
            self._entries.append(entry)
            if len(self._entries) > self.MAX_ENTRIES:
                self._entries = self._entries[-self.MAX_ENTRIES :]

    def get_recent(self, count: int = 10) -> list[HistoryEntry]:
        with self._lock:
            return list(self._entries[-count:])

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
