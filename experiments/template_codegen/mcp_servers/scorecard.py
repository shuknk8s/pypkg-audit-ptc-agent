"""Experiment-local Scorecard server with retry logic."""
from mcp.server.fastmcp import FastMCP

from experiments.template_codegen.mcp_servers.retry import get_with_retry

mcp = FastMCP("scorecard")


@mcp.tool()
def get_security_scorecard(owner: str, repo: str) -> dict:
    """Get OpenSSF Security Scorecard for a GitHub repository."""
    try:
        resp = get_with_retry(
            f"https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}",
            timeout=15,
            follow_redirects=True,
        )
        data = resp.json()
        checks = {}
        for check in data.get("checks", []):
            checks[check.get("name", "")] = check.get("score", -1)
        return {
            "repository": f"{owner}/{repo}",
            "overall_score": data.get("score"),
            "checks": checks,
            "source": "scorecard",
        }
    except Exception as e:
        return {"repository": f"{owner}/{repo}", "overall_score": None, "checks": {}, "source": "scorecard", "error": str(e)}


if __name__ == "__main__":
    mcp.run()
