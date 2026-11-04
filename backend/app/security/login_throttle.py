"""Bounded process-local login throttling by source address and identity."""

import hmac
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable


class LoginThrottle:
    def __init__(
        self,
        *,
        attempts: int = 5,
        ip_attempts: int = 30,
        window_seconds: int = 900,
        max_buckets: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.attempts = attempts
        self.ip_attempts = ip_attempts
        self.window_seconds = window_seconds
        self.max_buckets = max_buckets
        self._clock = clock
        self._key = secrets.token_bytes(32)
        self._buckets: OrderedDict[bytes, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def _bucket_keys(self, source_ip: str, username: str) -> tuple[bytes, bytes]:
        ip_digest = hmac.digest(self._key, f"ip:{source_ip}".encode(), "sha256")
        identity_digest = hmac.digest(
            self._key,
            f"identity:{source_ip}:{username}".encode(),
            "sha256",
        )
        return ip_digest, identity_digest

    def _current_attempts(self, key: bytes, now: float) -> deque[float]:
        attempts = self._buckets.get(key, deque())
        while attempts and now - attempts[0] >= self.window_seconds:
            attempts.popleft()
        return attempts

    def is_limited(self, source_ip: str, username: str) -> bool:
        now = self._clock()
        with self._lock:
            ip_key, identity_key = self._bucket_keys(source_ip, username)
            return (
                len(self._current_attempts(ip_key, now)) >= self.ip_attempts
                or len(self._current_attempts(identity_key, now)) >= self.attempts
            )

    def record_failure(self, source_ip: str, username: str) -> None:
        now = self._clock()
        with self._lock:
            for key in self._bucket_keys(source_ip, username):
                attempts = self._current_attempts(key, now)
                attempts.append(now)
                self._buckets[key] = attempts
                self._buckets.move_to_end(key)
                while len(self._buckets) > self.max_buckets:
                    self._buckets.popitem(last=False)

    def clear(self, source_ip: str, username: str) -> None:
        with self._lock:
            _ip_key, identity_key = self._bucket_keys(source_ip, username)
            self._buckets.pop(identity_key, None)

    def clear_all(self) -> None:
        with self._lock:
            self._buckets.clear()


login_throttle = LoginThrottle()
