"""Shared HTTP retry helpers for experiment MCP servers."""
import time
import httpx

MAX_RETRIES = 3
BACKOFF_BASE = 2


def get_with_retry(url: str, **kwargs) -> httpx.Response:
    timeout = kwargs.pop("timeout", 20)
    for attempt in range(MAX_RETRIES):
        try:
            resp = httpx.get(url, timeout=timeout, **kwargs)
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(BACKOFF_BASE * (attempt + 1))
                    continue
            resp.raise_for_status()
            return resp
        except (httpx.TimeoutException, httpx.ConnectError):
            if attempt < MAX_RETRIES - 1:
                time.sleep(BACKOFF_BASE * (attempt + 1))
                continue
            raise
    raise httpx.HTTPError(f"Failed after {MAX_RETRIES} retries")


def post_with_retry(url: str, **kwargs) -> httpx.Response:
    timeout = kwargs.pop("timeout", 20)
    for attempt in range(MAX_RETRIES):
        try:
            resp = httpx.post(url, timeout=timeout, **kwargs)
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(BACKOFF_BASE * (attempt + 1))
                    continue
            resp.raise_for_status()
            return resp
        except (httpx.TimeoutException, httpx.ConnectError):
            if attempt < MAX_RETRIES - 1:
                time.sleep(BACKOFF_BASE * (attempt + 1))
                continue
            raise
    raise httpx.HTTPError(f"Failed after {MAX_RETRIES} retries")
