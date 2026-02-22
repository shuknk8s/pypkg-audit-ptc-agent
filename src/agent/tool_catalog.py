def build_tool_catalog_summary(tools_by_server: dict[str, list[dict]]) -> str:
    lines: list[str] = ["## Available MCP Tool Servers\n"]
    for server_name, tools in sorted(tools_by_server.items()):
        tool_names = [t.get("name", "?") for t in tools]
        desc_parts = ", ".join(tool_names)
        lines.append(f"- **{server_name}** ({len(tools)} tools): {desc_parts}")
    return "\n".join(lines)


def build_tool_catalog_detail(generated_files: dict[str, str]) -> str:
    doc_sections: list[str] = []
    for filename, content in sorted(generated_files.items()):
        if filename.startswith("docs/") and filename.endswith(".md"):
            doc_sections.append(content.strip())
    if not doc_sections:
        return "(No tool documentation available.)"
    return "\n\n---\n\n".join(doc_sections)
