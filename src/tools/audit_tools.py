"""LangChain @tool wrappers for NVD, PyPI, and GitHub audit sources."""

from langchain_core.tools import tool

from src.mcp_servers.nvd import search_cves
from src.mcp_servers.pypi import get_package_metadata
from src.mcp_servers.github_api import get_release_notes as _get_release_notes


@tool
def nvd_cve_search(package_name: str, version: str) -> dict:
    """Search the NVD (National Vulnerability Database) for CVEs affecting a specific package version.

    Args:
        package_name: The Python package name to search for (e.g. "requests").
        version: The pinned version string to check (e.g. "2.28.0").

    Returns:
        A dict with keys:
          - package (str): the queried package name
          - version (str): the queried version
          - results (list[dict]): each item has cve_id, severity, cvss_score,
            summary, status ("affecting_pinned"|"not_relevant"|"needs_interpretation"),
            determination_method ("cpe_range"|"heuristic")
          - source (str): "nvd"
          - error (str, optional): present on HTTP/parse failure
    """
    return search_cves(package_name, version)


@tool
def pypi_package_info(package_name: str) -> dict:
    """Fetch PyPI metadata for a Python package.

    Args:
        package_name: The PyPI package name to look up (e.g. "requests").

    Returns:
        A dict with keys:
          - name (str): the package name
          - latest_version (str | None): latest published version on PyPI
          - home_page (str | None): project homepage URL
          - github_repository (str | None): inferred GitHub owner/repo (e.g. "psf/requests")
          - source (str): "pypi"
          - error (str, optional): present on HTTP/parse failure
    """
    return get_package_metadata(package_name)


@tool
def github_release_notes(repo: str, from_version: str, to_version: str) -> dict:
    """Fetch GitHub release notes for a repository between two version tags.

    Args:
        repo: Full GitHub repository in "owner/repo" format (e.g. "psf/requests").
              Pass "unknown/<package-name>" if the owner is not known — the tool
              will attempt a best-effort search by stars.
        from_version: The currently pinned version tag (e.g. "2.28.0").
        to_version: The target (latest) version tag (e.g. "2.32.3").

    Returns:
        A dict with keys:
          - repository (str): resolved "owner/repo"
          - from_version (str): the from version
          - to_version (str): the to version
          - notes (list[str]): up to 8 release note excerpts, each prefixed with tag
          - source (str): "github_api"
          - error (str, optional): present on HTTP/auth failure
    """
    if "/" in repo:
        owner, name = repo.split("/", 1)
    else:
        owner, name = "unknown", repo
    return _get_release_notes(owner, name, from_version, to_version)
