import time

from mcp.server.fastmcp import FastMCP
import httpx

mcp = FastMCP("license_check")


def _get_with_retry(url: str, *, max_retries: int = 3, backoff: int = 1, **kwargs) -> httpx.Response:
    timeout = kwargs.pop("timeout", 15)
    for attempt in range(max_retries):
        try:
            resp = httpx.get(url, timeout=timeout, **kwargs)
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < max_retries - 1:
                    time.sleep(backoff * (attempt + 1))
                    continue
            resp.raise_for_status()
            return resp
        except (httpx.TimeoutException, httpx.ConnectError):
            if attempt < max_retries - 1:
                time.sleep(backoff * (attempt + 1))
                continue
            raise
    raise httpx.HTTPError(f"Failed after {max_retries} retries")


@mcp.tool()
def check_license(package: str) -> dict:
    """Check the license of a PyPI package."""
    try:
        resp = _get_with_retry(
            f"https://pypi.org/pypi/{package}/json",
            timeout=15,
            follow_redirects=True,
        )
        data = resp.json()
        info = data.get("info", {})
        license_text = info.get("license") or ""
        classifiers = [c for c in (info.get("classifiers") or []) if "License" in c]
        return {
            "package": package,
            "license": license_text[:200],
            "license_classifiers": classifiers[:5],
            "source": "license_check",
        }
    except Exception as e:
        return {"package": package, "license": None, "license_classifiers": [], "source": "license_check", "error": str(e)}

if __name__ == "__main__":
    mcp.run()
