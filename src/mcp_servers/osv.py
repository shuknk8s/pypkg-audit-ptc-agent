from mcp.server.fastmcp import FastMCP
import httpx

mcp = FastMCP("osv")

@mcp.tool()
def query_vulnerability(package: str, version: str, ecosystem: str = "PyPI") -> dict:
    """Query OSV database for vulnerabilities affecting a specific package version."""
    try:
        resp = httpx.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": package, "ecosystem": ecosystem}, "version": version},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulns", [])
        results = []
        for v in vulns[:50]:
            results.append({
                "id": v.get("id", ""),
                "summary": (v.get("summary") or v.get("details", ""))[:300],
                "severity": _extract_severity(v),
                "aliases": v.get("aliases", [])[:5],
            })
        return {"package": package, "version": version, "results": results, "source": "osv"}
    except Exception as e:
        return {"package": package, "version": version, "results": [], "source": "osv", "error": str(e)}


def _extract_severity(vuln: dict) -> str:
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        if "CVSS" in score_str.upper():
            return score_str[:20]
    return "unknown"

if __name__ == "__main__":
    mcp.run()
