"""Detector interface.

Every detector is stateful across windows and sees the stream one window at a
time. It never sees the whole capture, and it is never told how many windows are
left -- which is exactly the constraint a live unidirectional feed imposes. A
detector that works here works on an endless stream.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from alerts.schema import Alert
from features.baseline import BaselineTracker
from features.extract import WindowFeatures


class Detector(ABC):
    name: str = "detector"
    threat_class: str = "UNKNOWN"

    # Suppress repeat alerts for the same entity for this long (capture time).
    # An ongoing SYN flood is one incident, not one incident per window.
    cooldown_s: float = 30.0

    def __init__(self) -> None:
        self._last_alert: dict[str, float] = {}

    @abstractmethod
    def on_window(self, wf: WindowFeatures, baselines: BaselineTracker) -> list[Alert]:
        """Inspect one window and return zero or more alerts."""

    def ready(self, key: str, ts: float) -> bool:
        """Cooldown gate. Call before emitting; call mark() after."""
        last = self._last_alert.get(key)
        return last is None or (ts - last) >= self.cooldown_s

    def mark(self, key: str, ts: float) -> None:
        self._last_alert[key] = ts
