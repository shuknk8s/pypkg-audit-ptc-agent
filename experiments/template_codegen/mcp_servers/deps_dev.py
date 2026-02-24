"""Experiment-local deps.dev server with retry logic."""
from mcp.server.fastmcp import FastMCP

from experiments.template_codegen.mcp_servers.retry import get_with_retry

mcp = FastMCP("deps_dev")


@mcp.tool()
def get_dependency_info(package: str, version: str) -> dict:
    """Get dependency graph info from deps.dev for a PyPI package version."""
    try:
        resp = get_with_retry(
            f"https://api.deps.dev/v3alpha/systems/pypi/packages/{package}/versions/{version}",
            timeout=15,
            follow_redirects=True,
        )
        data = resp.json()
        dep_count = len(data.get("links", []))
        advisories = data.get("advisoryKeys", [])
        return {
            "package": package,
            "version": version,
            "dependency_count": dep_count,
            "advisory_count": len(advisories),
            "advisories": [a.get("id", "") for a in advisories[:10]],
            "source": "deps_dev",
        }
    except Exception as e:
        return {
            "package": package,
            "version": version,
            "dependency_count": None,
            "advisory_count": None,
            "advisories": [],
            "source": "deps_dev",
            "error": str(e),
        }


if __name__ == "__main__":
    mcp.run()
