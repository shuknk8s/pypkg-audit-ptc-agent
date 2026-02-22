from mcp.server.fastmcp import FastMCP
import httpx

mcp = FastMCP("scorecard")

@mcp.tool()
def get_security_scorecard(owner: str, repo: str) -> dict:
    """Get OpenSSF Security Scorecard for a GitHub repository."""
    try:
        resp = httpx.get(
            f"https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}",
            timeout=15,
            follow_redirects=True,
        )
        resp.raise_for_status()
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
