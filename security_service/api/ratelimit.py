"""
security_service/api/ratelimit.py

A per-caller rate limit: at most `limit_per_minute` requests in any rolling 60 seconds, counted separately for each caller,
so one noisy caller cannot use up another's allowance. In memory and per process: enough for one service instance, and
the reason a deployment behind several instances needs a shared limiter later (recorded in the README).

When a caller is over the limit, `check` says how many seconds to wait, which becomes the Retry-After header.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from typing import Callable

WINDOW_SECONDS = 60.0


class RateLimiter:
    def __init__(self, limit_per_minute: int, clock: Callable[[], float] = time.monotonic):
        if limit_per_minute < 1:
            raise ValueError("limit_per_minute must be at least 1")
        self._limit = limit_per_minute
        self._clock = clock
        self._seen: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, caller: str) -> tuple[bool, int]:
        """(allowed, seconds to wait). A request that is allowed is counted; one that is refused is not."""
        now = self._clock()
        with self._lock:
            window = self._seen.setdefault(caller, deque())
            while window and now - window[0] >= WINDOW_SECONDS:
                window.popleft()
            if len(window) >= self._limit:
                return False, max(1, math.ceil(WINDOW_SECONDS - (now - window[0])))
            window.append(now)
            if len(self._seen) > 1000:                           # forget callers who have been quiet for a whole window
                for name in [n for n, w in self._seen.items() if not w or now - w[-1] >= WINDOW_SECONDS]:
                    del self._seen[name]
            return True, 0


def demo() -> None:
    now = [1000.0]
    limiter = RateLimiter(3, clock=lambda: now[0])

    assert [limiter.check("a")[0] for _ in range(3)] == [True, True, True]
    allowed, wait = limiter.check("a")
    assert not allowed and 1 <= wait <= 60                                     # the fourth is refused, with a wait to retry after
    assert limiter.check("b")[0] is True                                      # another caller is unaffected

    now[0] += 30                                                               # half a window later: still refused, and the wait shrinks
    allowed, wait_later = limiter.check("a")
    assert not allowed and wait_later < wait
    assert limiter.check("a")[0] is False and limiter.check("a")[1] >= 1       # refused requests are not counted against the caller

    now[0] += 31                                                               # the first three have left the window
    assert limiter.check("a")[0] is True

    # sliding, not fixed: requests spread over time are never refused
    slow = RateLimiter(2, clock=lambda: now[0])
    for _ in range(10):
        now[0] += 31
        assert slow.check("c")[0] is True

    # many threads at once: exactly `limit` get through, never more
    limiter2 = RateLimiter(40)
    results: list[bool] = []

    def hammer():
        results.append(limiter2.check("x")[0])

    threads = [threading.Thread(target=hammer) for _ in range(200)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(results) == 40 and len(results) == 200

    for bad in (0, -5):
        try:
            RateLimiter(bad)
            raise AssertionError("a limit below 1 must be refused")
        except ValueError:
            pass
    print("api.ratelimit OK: per-caller rolling window, correct Retry-After, refused requests not counted, exact under 200 concurrent threads")


if __name__ == "__main__":
    demo()
