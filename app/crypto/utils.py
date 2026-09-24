"""Utility functions for hashing, encoding, and timing."""

import hashlib
import base64
import time
from typing import Tuple, Any, Callable


def sha256_bytes(data: bytes) -> str:
    """Compute hex SHA-256 checksum of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def b64_encode(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode("ascii")


def b64_decode(data_str: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(data_str.encode("ascii"))


def benchmark_execution(func: Callable, *args, iterations: int = 1, **kwargs) -> Tuple[Any, float]:
    """Execute function and return (result, average_elapsed_seconds)."""
    start = time.perf_counter()
    result = None
    for _ in range(iterations):
        result = func(*args, **kwargs)
    elapsed = (time.perf_counter() - start) / iterations
    return result, elapsed
