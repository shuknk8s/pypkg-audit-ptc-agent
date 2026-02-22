from mcp.server.fastmcp import FastMCP
import re

import httpx

mcp = FastMCP("pypi")


@mcp.tool()
def get_package_metadata(package_name: str) -> dict:
    try:
        resp = httpx.get(
            f"https://pypi.org/pypi/{package_name}/json",
            timeout=15,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})
        project_urls = info.get("project_urls") or {}
        home_page = (
            info.get("home_page")
            or info.get("project_url")
            or project_urls.get("Homepage")
            or project_urls.get("Source")
            or project_urls.get("Repository")
        )
        github_repository = None
        candidates = [
            home_page,
            info.get("project_url"),
            project_urls.get("Source"),
            project_urls.get("Repository"),
            project_urls.get("Homepage"),
        ]
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            m = re.search(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", candidate)
            if m:
                github_repository = m.group(1).rstrip("/")
                break
        return {
            "name": package_name,
            "latest_version": info.get("version"),
            "home_page": home_page,
            "github_repository": github_repository,
            "source": "pypi",
        }
    except Exception as e:
        return {
            "name": package_name,
            "latest_version": None,
            "home_page": None,
            "github_repository": None,
            "source": "pypi",
            "error": str(e),
        }


if __name__ == "__main__":
    mcp.run()
