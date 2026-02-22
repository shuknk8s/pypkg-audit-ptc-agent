from mcp.server.fastmcp import FastMCP
import os
import httpx

mcp = FastMCP("github_api")


@mcp.tool()
def get_release_notes(owner: str, repo: str, from_version: str, to_version: str) -> dict:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    repo_full = f"{owner}/{repo}"
    try:
        if owner == "unknown":
            # best-effort repo discovery
            q = repo
            s = httpx.get(
                "https://api.github.com/search/repositories",
                params={"q": q, "sort": "stars", "order": "desc", "per_page": 1},
                headers=headers,
                timeout=15,
                follow_redirects=True,
            )
            s.raise_for_status()
            items = (s.json() or {}).get("items", [])
            if isinstance(items, list) and items:
                full_name = items[0].get("full_name")
                if isinstance(full_name, str) and "/" in full_name:
                    repo_full = full_name
        releases = httpx.get(
            f"https://api.github.com/repos/{repo_full}/releases",
            params={"per_page": 10},
            headers=headers,
            timeout=20,
            follow_redirects=True,
        )
        releases.raise_for_status()
        notes = []
        for rel in releases.json() if isinstance(releases.json(), list) else []:
            tag = rel.get("tag_name") or rel.get("name") or "release"
            body = (rel.get("body") or "").strip()
            if body:
                notes.append(f"{tag}: {body[:300]}")
        return {
            "repository": repo_full,
            "from_version": from_version,
            "to_version": to_version,
            "notes": notes[:8],
            "source": "github_api",
        }
    except Exception as e:
        return {
            "repository": repo_full,
            "from_version": from_version,
            "to_version": to_version,
            "notes": [],
            "source": "github_api",
            "error": str(e),
        }


if __name__ == "__main__":
    mcp.run()
