"""Experiment-local EPSS server with retry logic."""
from mcp.server.fastmcp import FastMCP

from experiments.template_codegen.mcp_servers.retry import get_with_retry

mcp = FastMCP("epss")


@mcp.tool()
def get_exploit_probability(cve_id: str) -> dict:
    """Get EPSS exploit probability score for a CVE."""
    try:
        resp = get_with_retry(
            f"https://api.first.org/data/v1/epss?cve={cve_id}",
            timeout=15,
            follow_redirects=True,
        )
        data = resp.json()
        entries = data.get("data", [])
        if entries:
            entry = entries[0]
            return {
                "cve_id": cve_id,
                "epss_score": float(entry.get("epss", 0.0)),
                "percentile": float(entry.get("percentile", 0.0)),
                "source": "epss",
            }
        return {"cve_id": cve_id, "epss_score": None, "percentile": None, "source": "epss"}
    except Exception as e:
        return {"cve_id": cve_id, "epss_score": None, "percentile": None, "source": "epss", "error": str(e)}


if __name__ == "__main__":
    mcp.run()
