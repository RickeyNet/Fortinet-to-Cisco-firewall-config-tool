#!/usr/bin/env python3
"""Shared concurrency and retry helpers for importer/cleanup scripts."""

import concurrent.futures
import random
import re
import time
from typing import Callable, Iterable, Optional, Tuple, TypeVar


T = TypeVar("T")

# Common API transient error fragments that should trigger a retry.
TRANSIENT_ERROR_TOKENS = (
    "too many",
    "rate limit",
    "timeout",
    "temporarily",
)

# Transient HTTP status codes matched as standalone numbers (word-boundary)
# so an object *name* that merely contains "423" does not trigger retries.
_TRANSIENT_STATUS_RE = re.compile(r"\b(423|429|503|504)\b")


def is_transient_api_error(error_msg: Optional[str]) -> bool:
    """Return True when an error looks transient and retryable."""
    if not error_msg:
        return False
    msg = str(error_msg).lower()
    if _TRANSIENT_STATUS_RE.search(msg):
        return True
    return any(token in msg for token in TRANSIENT_ERROR_TOKENS)


def run_with_retry(
    operation: Callable[[], Tuple[bool, Optional[str]]],
    max_attempts: int = 4,
    base_backoff: float = 0.3,
    max_jitter: float = 0.25,
    should_retry: Callable[[Optional[str]], bool] = is_transient_api_error,
) -> Tuple[bool, Optional[str]]:
    """Run an operation with exponential backoff retries on transient failures."""
    attempts = max(1, max_attempts)
    backoff = max(0.0, base_backoff)

    for attempt in range(attempts):
        success, result = operation()
        if success:
            return True, result

        if attempt >= attempts - 1 or not should_retry(result):
            return False, result

        time.sleep(backoff + random.uniform(0.0, max_jitter))
        backoff *= 2

    return False, "unknown retry failure"


def run_indexed_thread_pool(max_workers: int, items: Iterable[T], worker: Callable[[int, T], None]) -> None:
    """Execute a worker for each indexed item using a bounded thread pool."""
    workers = max(1, max_workers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        for idx, item in enumerate(items):
            futures.append(executor.submit(worker, idx, item))
        # Propagate any unhandled worker exceptions
        for future in concurrent.futures.as_completed(futures):
            future.result()
