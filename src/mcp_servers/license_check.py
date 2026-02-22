from mcp.server.fastmcp import FastMCP
import httpx

mcp = FastMCP("license_check")

@mcp.tool()
def check_license(package: str) -> dict:
    """Check the license of a PyPI package."""
    try:
        resp = httpx.get(
            f"https://pypi.org/pypi/{package}/json",
            timeout=15,
            follow_redirects=True,
        )
        resp.raise_for_status()
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
