import time
from collections import defaultdict
from fastapi import HTTPException, Request, status

from src.settings import settings
from src.share.helpers import resolve_client_ip

_ACTIVE_LIMITERS: list["RateLimiter"] = []


def reset_all_rate_limiters() -> None:
    """Resets call histories across all active RateLimiter instances."""
    for limiter in _ACTIVE_LIMITERS:
        limiter.reset()


class RateLimiter:
    """In-memory sliding window rate limiter dependency for FastAPI."""

    def __init__(
        self,
        requests: int | None = None,
        window_seconds: int | None = None,
    ):
        self._custom_requests = requests
        self._custom_window = window_seconds
        self._history: dict[str, list[float]] = defaultdict(list)
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

    def reset(self) -> None:
        self._history.clear()

    async def __call__(self, request: Request) -> None:
        if not settings.rate_limit_enabled:
            return

        client_ip = resolve_client_ip(request) or "127.0.0.1"
        now = time.monotonic()
        cutoff = now - self.window_seconds

        # Retain only timestamps inside the current window
        timestamps = [t for t in self._history[client_ip] if t > cutoff]
        self._history[client_ip] = timestamps

        if len(timestamps) >= self.requests:
            retry_after = max(1, int(self.window_seconds - (now - timestamps[0])) + 1)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )

        self._history[client_ip].append(now)

