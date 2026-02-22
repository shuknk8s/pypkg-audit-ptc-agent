# Tool: nvd_cve_search

## Purpose
Search the NVD (National Vulnerability Database) for CVEs affecting a specific Python
package at a pinned version. Applies CPE range matching and heuristic version
comparisons to classify each CVE.

## Signature
```
nvd_cve_search(package_name: str, version: str) -> PTC_Summary
```

## Arguments
- `package_name` (str): PyPI package name, lowercase (e.g. `"requests"`, `"flask"`)
- `version` (str): exact pinned version string (e.g. `"2.28.0"`)

## PTC return value (compact — full data written to file)
```json
{
  "ptc_data_path": "/tmp/ptc_audit/{package}_nvd.json",
  "package": "requests",
  "version": "2.28.0",
  "total_found": 12,
  "affecting_pinned": 3,
  "not_relevant": 7,
  "needs_interpretation": 2,
  "severity_counts": {"critical": 1, "high": 2, "medium": 6, "low": 3},
  "source": "nvd"
}
```

## Full data schema (at ptc_data_path)
```json
{
  "package": "str",
  "version": "str",
  "results": [
    {
      "cve_id": "CVE-2023-XXXXX",
      "severity": "critical|high|medium|low|unknown",
      "cvss_score": 9.8,
      "summary": "str — full CVE description",
      "status": "affecting_pinned|not_relevant|needs_interpretation",
      "determination_method": "cpe_range|heuristic"
    }
  ],
  "source": "nvd",
  "error": "str — only present on HTTP/parse failure"
}
```

## Error handling
- On HTTP failure: `ptc_data_path` still written; compact summary has `"error": "str"`
- On empty results: `total_found = 0`, `results = []`, no error key

## Usage pattern (PTD + PTC)
1. Read this file ONCE before calling the tool for the first time
2. Call `nvd_cve_search(package, version)` — get compact summary in ToolMessage
3. Use compact `affecting_pinned`, `severity_counts` for risk assessment
4. Only call `read_file(ptc_data_path)` if you need specific CVE details (e.g. for cve-interpreter delegation)
