import json
import os


_RISK_SCORE = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def _deterministic_priority(package_results: list[dict]) -> list[dict]:
    def _key(item: dict) -> tuple[int, int, int, str]:
        risk = _RISK_SCORE.get(str(item.get("risk_rating", "low")).lower(), 1)
        cves = int(item.get("total_cves_found") or 0)
        behind = int(item.get("versions_behind") or 0)
        name = str(item.get("package") or "")
        return (-risk, -cves, -behind, name)

    ordered = sorted(package_results, key=_key)
    prioritized = []
    for idx, row in enumerate(ordered, start=1):
        prioritized.append(
            {
                "rank": idx,
                "package": row.get("package"),
                "risk_rating": row.get("risk_rating"),
                "total_cves_found": row.get("total_cves_found"),
                "versions_behind": row.get("versions_behind"),
                "upgrade_recommendation": row.get("upgrade_recommendation"),
            }
        )
    return prioritized


def _deterministic_recommendation(prioritized_packages: list[dict]) -> str:
    if not prioritized_packages:
        return "No packages to synthesize."
    top = prioritized_packages[0]
    return (
        f"Start with {top.get('package')} (risk={top.get('risk_rating')}, "
        f"cves={top.get('total_cves_found')}) and proceed by ranked order."
    )


def _detailed_bullet_summary(prioritized_packages: list[dict]) -> str:
    if not prioritized_packages:
        return "- No packages provided for synthesis."
    lines = ["- Senior analyst summary: prioritize remediation by confirmed exposure first, then by upgrade complexity."]
    top = prioritized_packages[:3]
    for item in top:
        lines.append(
            f"- Rank {item.get('rank')}: `{item.get('package')}` "
            f"(risk={item.get('risk_rating')}, cves={item.get('total_cves_found')}, "
            f"versions_behind={item.get('versions_behind')}) -> {item.get('upgrade_recommendation')}"
        )
    remaining = prioritized_packages[3:]
    if remaining:
        names = ", ".join(str(x.get("package")) for x in remaining)
        lines.append(f"- Remaining packages in follow-up wave: {names}.")
    lines.append("- Rollout guidance: apply staged deployment for high-risk items; validate authentication/networking paths before production.")
    return "\n".join(lines)


async def _llm_narrative(prioritized_packages: list[dict], model: str) -> str:
    if not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is missing")
    try:
        from langchain_openai import ChatOpenAI
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(f"langchain_openai unavailable: {exc}") from exc

    llm = ChatOpenAI(model=model, timeout=30)
    prompt = (
        "You are a senior cybersecurity analyst. Given prioritized package data, "
        "write a concise but detailed bullet-pointed risk summary.\n"
        "Requirements:\n"
        "- Use 4-7 bullets\n"
        "- Explain why top-ranked packages are first\n"
        "- Mention tradeoffs and rollout/testing guidance\n"
        "- Keep findings evidence-driven from the data only\n\n"
        f"DATA:\n{json.dumps(prioritized_packages, ensure_ascii=False)}"
    )
    resp = await llm.ainvoke(prompt)
    content = getattr(resp, "content", "")
    if isinstance(content, list):
        return "".join(str(part) for part in content).strip()
    return str(content).strip()


async def synthesize_results(
    package_results: list[dict],
    *,
    use_llm: bool,
    llm_model: str = "gpt-4o-mini",
) -> dict:
    prioritized_packages = _deterministic_priority(package_results)
    deterministic_rationale = _deterministic_recommendation(prioritized_packages)

    synthesis = {
        "prioritized_packages": prioritized_packages,
        "recommendation_rationale": deterministic_rationale,
        "detailed_summary": _detailed_bullet_summary(prioritized_packages),
        "llm_used": False,
        "llm_narrative": None,
        "llm_error": None,
    }
    if use_llm:
        try:
            synthesis["llm_narrative"] = await _llm_narrative(prioritized_packages, model=llm_model)
            synthesis["llm_used"] = True
        except Exception as exc:
            synthesis["llm_error"] = str(exc)
    return synthesis
