# Tool: pypi_package_info

## Purpose
Fetch package metadata from PyPI — latest version, release history, and inferred
GitHub repository. Use this first to establish the version gap before CVE analysis.

## Signature
```
pypi_package_info(package_name: str) -> PTC_Summary
```

## Arguments
- `package_name` (str): PyPI package name (e.g. `"requests"`, `"flask"`)

## PTC return value (compact — full data written to file)
```json
{
  "ptc_data_path": "/tmp/ptc_audit/{package}_pypi.json",
  "name": "requests",
  "latest_version": "2.32.3",
  "versions_behind": 4,
  "github_repository": "psf/requests",
  "source": "pypi"
}
```

## Full data schema (at ptc_data_path)
```json
{
  "name": "str",
  "latest_version": "str | null",
  "home_page": "str | null",
  "github_repository": "str | null  — in owner/repo format",
  "release_count": 42,
  "source": "pypi",
  "error": "str — only present on HTTP/parse failure"
}
```

## Error handling
- On HTTP failure: compact summary has `"error": "str"`, `latest_version` may be null
- `github_repository` is null if the project page does not link to GitHub

## Usage pattern (PTD + PTC)
1. Read this file ONCE before calling the tool for the first time
2. Call `pypi_package_info(package_name)` — get compact summary with latest_version and github_repository
3. Use `latest_version` to compute `versions_behind` and as `to_version` for github_release_notes
4. Use `github_repository` as the `repo` argument to github_release_notes
5. Only call `read_file(ptc_data_path)` if you need full release history
