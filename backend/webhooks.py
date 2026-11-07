"""Signed webhook helpers.

Developer: NAKARIN SAKULTHAI
License: MIT License
"""
from __future__ import annotations

import hashlib
import hmac
import time
from threading import Lock


class WebhookGuard:
    def __init__(self, secret: str, tolerance_seconds: int = 300) -> None:
        self.secret = secret.encode("utf-8")
        self.tolerance_seconds = tolerance_seconds
        self._seen: set[str] = set()
        self._lock = Lock()

    def signature(self, timestamp: str, raw_body: bytes) -> str:
        message = f"{timestamp}.".encode("utf-8") + raw_body
        return hmac.new(self.secret, message, hashlib.sha256).hexdigest()

    def verify(self, timestamp: str, raw_body: bytes, supplied: str, event_id: str) -> tuple[bool, str]:
        if not timestamp.isdigit():
            return False, "invalid timestamp"
        if abs(int(time.time()) - int(timestamp)) > self.tolerance_seconds:
            return False, "stale webhook"
        expected = self.signature(timestamp, raw_body)
        if not hmac.compare_digest(expected, supplied.removeprefix("sha256=")):
            return False, "invalid signature"
        with self._lock:
            if event_id in self._seen:
                return False, "replayed event"
            self._seen.add(event_id)
        return True, "verified"

    def reset_for_tests(self) -> None:
        with self._lock:
            self._seen.clear()
