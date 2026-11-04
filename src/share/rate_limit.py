import time
from collections import OrderedDict
from fastapi import HTTPException, Request, status

from src.settings import settings
from src.share.helpers import resolve_client_ip

_ACTIVE_LIMITERS: list["RateLimiter"] = []


def reset_all_rate_limiters() -> None:
    """Resets call histories across all active RateLimiter instances."""
    for limiter in _ACTIVE_LIMITERS:
        limiter.reset()


class RateLimiter:
    """In-memory sliding window rate limiter with O(1) LRU eviction and dual-axis throttling."""

    def __init__(
        self,
        requests: int | None = None,
        window_seconds: int | None = None,
        max_tracked_keys: int | None = None,
    ) -> None:
        self._custom_requests = requests
        self._custom_window = window_seconds
        self._custom_max_keys = max_tracked_keys
        self._history: OrderedDict[str, list[float]] = OrderedDict()
        _ACTIVE_LIMITERS.append(self)

    @property
    def requests(self) -> int:
        return (
            self._custom_requests
            if self._custom_requests is not None
            else settings.auth_rate_limit_requests
        )

    @property
    def window_seconds(self) -> int:
        return (
            self._custom_window
            if self._custom_window is not None
            else settings.auth_rate_limit_window_seconds
        )

    @property
    def max_tracked_keys(self) -> int:
        return (
            self._custom_max_keys
            if self._custom_max_keys is not None
            else getattr(settings, "rate_limit_max_tracked_keys", 10_000)
        )

    def reset(self) -> None:
        self._history.clear()

    def _check_single_key(self, key: str, now: float) -> None:
        cutoff = now - self.window_seconds
        existing = self._history.get(key, [])
        timestamps = [t for t in existing if t > cutoff]

        if len(timestamps) >= self.requests:
            retry_after = max(1, int(self.window_seconds - (now - timestamps[0])) + 1)
            # Retain valid timestamps and keep fresh
            self._history[key] = timestamps
            self._history.move_to_end(key)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )

        timestamps.append(now)
        self._history[key] = timestamps
        self._history.move_to_end(key)

        # Enforce strict LRU memory cap
        while len(self._history) > self.max_tracked_keys:
            self._history.popitem(last=False)

    async def check_request_and_account(
        self,
        request: Request,
        account_identifier: str | None = None,
    ) -> None:
        """Enforces dual-axis rate limiting across both client IP and account identifier."""
        if not settings.rate_limit_enabled:
            return

        client_ip = resolve_client_ip(request) or "127.0.0.1"
        now = time.monotonic()

        # Axis 1: Client IP throttle (only if not already checked in this request lifecycle)
        if not (hasattr(request, "state") and getattr(request.state, "_rate_limited_ip", False)):
            self._check_single_key(f"ip:{client_ip}", now)
            if hasattr(request, "state"):
                request.state._rate_limited_ip = True

        # Axis 2: Account identifier throttle (guards against distributed credential stuffing)
        if account_identifier and account_identifier.strip():
            norm_account = account_identifier.strip().lower()
            self._check_single_key(f"acct:{norm_account}", now)

    async def __call__(self, request: Request) -> None:
        if not settings.rate_limit_enabled:
            return
        client_ip = resolve_client_ip(request) or "127.0.0.1"
        now = time.monotonic()
        if not (hasattr(request, "state") and getattr(request.state, "_rate_limited_ip", False)):
            self._check_single_key(f"ip:{client_ip}", now)
            if hasattr(request, "state"):
                request.state._rate_limited_ip = True
