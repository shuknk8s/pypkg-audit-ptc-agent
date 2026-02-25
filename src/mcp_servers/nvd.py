import re
import time

from mcp.server.fastmcp import FastMCP
import httpx

mcp = FastMCP("nvd")

MAX_RETRIES = 3
BACKOFF_BASE = 2  # seconds — NVD rate limit is 5 req/30s without API key


def _get_with_retry(url: str, **kwargs) -> httpx.Response:
    """HTTP GET with retry on transient errors (429, 5xx, timeouts)."""
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
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            if attempt < MAX_RETRIES - 1:
                time.sleep(BACKOFF_BASE * (attempt + 1))
                continue
            raise
    raise httpx.HTTPError(f"Failed after {MAX_RETRIES} retries")


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


_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)*")

# Patterns that indicate an upper bound: "before X", "prior to X", "<= X", "< X",
# "through X", "up to X", "upgrade to X or higher" (implies affects < X)
_UPPER_BOUND_RE = re.compile(
    r"(?:before|prior\s+to|<\s*=?|through|up\s+to)"
    r"\s*(?:version\s*)?"
    r"(\d+\.\d+(?:\.\d+)*)",
    re.IGNORECASE,
)

# "upgrade … to version X or higher" → affects versions < X
_UPGRADE_TO_RE = re.compile(
    r"upgrade\s+\S+\s+to\s+(?:version\s*)?(\d+\.\d+(?:\.\d+)*)\s+or\s+(?:higher|later|above)",
    re.IGNORECASE,
)

# "versions = X.Y.Z" or "versions <= X.Y.Z" (equality/lte in summary text)
_VERSIONS_EQ_RE = re.compile(
    r"versions?\s*[<>]?=\s*(\d+\.\d+(?:\.\d+)*)",
    re.IGNORECASE,
)


def _check_summary_version(package: str, version: str, summary: str) -> str | None:
    """Parse version ranges from CVE summary text.

    Returns "not_relevant" or "affecting_pinned" if a determination can be made,
    or None if the summary doesn't contain parseable version info for this package.
    """
    lower = summary.lower()
    pkg_lower = package.lower()
    if pkg_lower not in lower:
        return None

    # Collect upper-bound versions from all patterns
    upper_bounds = []
    for m in _UPPER_BOUND_RE.finditer(lower):
        upper_bounds.append(m.group(1))
    for m in _UPGRADE_TO_RE.finditer(lower):
        upper_bounds.append(m.group(1))
    for m in _VERSIONS_EQ_RE.finditer(lower):
        upper_bounds.append(m.group(1))

    if not upper_bounds:
        return None

    # Use the highest upper bound found — if pinned version >= all bounds,
    # the CVE doesn't affect this version
    for bound in upper_bounds:
        if _cmp(version, bound) >= 0:
            continue
        # version < this bound → possibly affected
        return "affecting_pinned"

    # version >= all upper bounds → not affected
    return "not_relevant"


@mcp.tool()
def search_cves(package: str, version: str | None = None) -> dict:
    try:
        resp = _get_with_retry(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": package, "resultsPerPage": 50},
            timeout=20,
            follow_redirects=True,
        )
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
            has_any_cpe = False
            cfgs = cve.get("configurations", [])
            for cfg in cfgs if isinstance(cfgs, list) else []:
                nodes = cfg.get("nodes", [])
                for node in nodes if isinstance(nodes, list) else []:
                    for match in node.get("cpeMatch", []) if isinstance(node.get("cpeMatch", []), list) else []:
                        has_any_cpe = True
                        criteria = str(match.get("criteria") or "").lower()
                        parts = criteria.split(":")
                        cpe_product = parts[4] if len(parts) > 4 else ""
                        if cpe_product == package.lower():
                            matched_cpe = True
                            if version and _is_in_range(version, match):
                                status = "affecting_pinned"
                            elif version:
                                status = "not_relevant"
                            else:
                                status = "needs_interpretation"
            cpe_excluded = False
            if not matched_cpe:
                if has_any_cpe:
                    # CVE has CPE data for other products but not ours —
                    # NVD explicitly tied this CVE to other software.
                    status = "not_relevant"
                    cpe_excluded = True
                else:
                    # No CPE data at all — fall back to summary heuristics
                    lower_summary = summary.lower()
                    if package.lower() not in lower_summary:
                        status = "not_relevant"
                    elif version:
                        summary_status = _check_summary_version(package, version, summary)
                        if summary_status is not None:
                            status = summary_status
            results.append(
                {
                    "cve_id": _clean_text(cve_id),
                    "severity": _clean_text(severity),
                    "cvss_score": cvss_score,
                    "summary": _clean_text(summary),
                    "status": status,
                    "determination_method": (
                        "cpe_range" if matched_cpe and status in {"affecting_pinned", "not_relevant"}
                        else "summary_version" if not matched_cpe and not cpe_excluded and status in {"affecting_pinned", "not_relevant"} and package.lower() in summary.lower()
                        else "heuristic"
                    ),
                }
            )
        return {
            "package": package,
            "version": version,
            "results": results,
            "source": "nvd",
        }
    except Exception as e:
        return {
            "package": package,
            "version": version,
            "results": [],
            "source": "nvd",
            "error": str(e),
        }


if __name__ == "__main__":
    mcp.run()
