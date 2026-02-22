# Tool: github_release_notes

## Purpose
Fetch GitHub release notes between two version tags to identify breaking changes,
deprecations, and upgrade risk signals. Requires `pypi_package_info` to be called
first to obtain the `github_repository` field.

## Signature
```
github_release_notes(repo: str, from_version: str, to_version: str) -> PTC_Summary
```

## Arguments
- `repo` (str): GitHub repository in `"owner/repo"` format (e.g. `"psf/requests"`).
  Pass `"unknown/{package_name}"` if the owner is not yet known.
- `from_version` (str): the currently pinned version tag (e.g. `"2.28.0"`)
- `to_version` (str): the target/latest version tag (e.g. `"2.32.3"`)

## PTC return value (compact — full data written to file)
```json
{
  "ptc_data_path": "/tmp/ptc_audit/{package}_github.json",
  "repository": "psf/requests",
  "from_version": "2.28.0",
  "to_version": "2.32.3",
  "release_count": 4,
  "breaking_hints_found": true,
  "breaking_keywords": ["deprecated", "removed"],
  "source": "github_api"
}
```

## Full data schema (at ptc_data_path)
```json
{
  "repository": "str",
  "from_version": "str",
  "to_version": "str",
  "notes": ["str — up to 8 excerpts, each prefixed with version tag"],
  "source": "github_api",
  "error": "str — only present on HTTP/auth failure"
}
```

## Breaking change keywords scanned
`breaking`, `deprecated`, `removed`, `migration`, `incompatible`

## Error handling
- On HTTP failure or missing GITHUB_TOKEN: compact summary has `"error": "str"`
- On private/nonexistent repo: `"error": "repository not found"`
- On no releases found in range: `release_count = 0`, `notes = []`

## Usage pattern (PTD + PTC)
1. Read this file ONCE before calling the tool for the first time
2. Only call AFTER `pypi_package_info` — you need `github_repository` and `latest_version`
3. Call `github_release_notes(repo, pinned_version, latest_version)`
4. Use compact `breaking_hints_found` and `breaking_keywords` for risk assessment
5. Only call `read_file(ptc_data_path)` if you need full release note text for changelog-analyst delegation
