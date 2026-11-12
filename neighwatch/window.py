"""Bounded sliding window counter with per-key alert cooldown."""

from __future__ import annotations

from collections import deque


class SlidingWindowCounter:
    """Bounded packet-timestamp sliding window counter with per-key alert cooldown."""

    def __init__(self, window_sec: float, max_keys: int = 4096) -> None:
        self.window_sec = window_sec
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = {}
        self._last_alert: dict[str, float] = {}

    def record(self, key: str, ts: float, threshold: int) -> tuple[int, bool, bool]:
        """Record packet timestamp for key; return (count_in_window, triggered, in_cooldown)."""
        if self.window_sec <= 0 or threshold <= 0:
            return 0, False, False

        cutoff = ts - self.window_sec
        dq = self._events.get(key)
        if dq is None:
            if len(self._events) >= self.max_keys:
                self._evict_stale(cutoff)
            if len(self._events) >= self.max_keys:
                oldest_key = next(iter(self._events))
                del self._events[oldest_key]
                self._last_alert.pop(oldest_key, None)
            dq = deque()
            self._events[key] = dq

        dq.append(ts)
        while dq and dq[0] < cutoff:
            dq.popleft()

        count = len(dq)
        if count < threshold:
            return count, False, False

        last = self._last_alert.get(key)
        if last is not None and (ts - last) < self.window_sec:
            return count, False, True

        self._last_alert[key] = ts
        return count, True, False

    def _evict_stale(self, cutoff: float) -> None:
        stale = [k for k, dq in self._events.items() if not dq or dq[-1] < cutoff]
        for k in stale:
            del self._events[k]
            self._last_alert.pop(k, None)
