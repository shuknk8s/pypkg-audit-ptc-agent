from mcp.server.fastmcp import FastMCP
import httpx

mcp = FastMCP("nvd")


def _clean_text(value: str) -> str:
    text = str(value or "")
    text = text.encode("utf-8", "ignore").decode("utf-8", "ignore")
    return "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = []
    for token in str(value or "").split("."):
        digits = "".join(ch for ch in token if ch.isdigit())
        if digits == "":
            break
        parts.append(int(digits))
    return tuple(parts)


def _cmp(a: str, b: str) -> int:
    at = _version_tuple(a)
    bt = _version_tuple(b)
    if not at or not bt:
        return 0
    max_len = max(len(at), len(bt))
    at = at + (0,) * (max_len - len(at))
    bt = bt + (0,) * (max_len - len(bt))
    if at < bt:
        return -1
    if at > bt:
        return 1
    return 0


def _is_in_range(version: str, match: dict) -> bool:
    # NVD range keys commonly appear on cpeMatch entries.
    vsi = match.get("versionStartIncluding")
    vse = match.get("versionStartExcluding")
    vei = match.get("versionEndIncluding")
    vee = match.get("versionEndExcluding")
    if vsi and _cmp(version, vsi) < 0:
        return False
    if vse and _cmp(version, vse) <= 0:
        return False
    if vei and _cmp(version, vei) > 0:
        return False
    if vee and _cmp(version, vee) >= 0:
        return False
    return True


@mcp.tool()
def search_cves(package_name: str, version: str | None = None) -> dict:
    try:
        resp = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": package_name, "resultsPerPage": 50},
            timeout=20,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()
        results = []
        for row in data.get("vulnerabilities", []):
            cve = row.get("cve", {})
            cve_id = cve.get("id")
            severity = "unknown"
            cvss_score = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss = entries[0].get("cvssData", {})
                    severity = str(cvss.get("baseSeverity") or entries[0].get("baseSeverity") or "unknown").lower()
                    cvss_score = cvss.get("baseScore")
                    break
            summary = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    summary = d.get("value", "")
                    break
            status = "needs_interpretation"
            matched_cpe = False
            cfgs = cve.get("configurations", [])
            for cfg in cfgs if isinstance(cfgs, list) else []:
                nodes = cfg.get("nodes", [])
                for node in nodes if isinstance(nodes, list) else []:
                    for match in node.get("cpeMatch", []) if isinstance(node.get("cpeMatch", []), list) else []:
                        criteria = str(match.get("criteria") or "").lower()
                        if package_name.lower() in criteria:
                            matched_cpe = True
                            if version and _is_in_range(version, match):
                                status = "affecting_pinned"
                            elif version:
                                status = "not_relevant"
                            else:
                                status = "needs_interpretation"
            if not matched_cpe:
                # fallback heuristic for keyword-only matches
                lower_summary = summary.lower()
                if package_name.lower() not in lower_summary:
                    status = "not_relevant"
            results.append(
                {
                    "cve_id": _clean_text(cve_id),
                    "severity": _clean_text(severity),
                    "cvss_score": cvss_score,
                    "summary": _clean_text(summary),
                    "status": status,
                    "determination_method": "cpe_range" if status in {"affecting_pinned", "not_relevant"} else "heuristic",
                }
            )
        return {
            "package": package_name,
            "version": version,
            "results": results,
            "source": "nvd",
        }
    except Exception as e:
        return {
            "package": package_name,
            "version": version,
            "results": [],
            "source": "nvd",
            "error": str(e),
        }


if __name__ == "__main__":
    mcp.run()
