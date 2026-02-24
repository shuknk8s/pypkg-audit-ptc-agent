def build_tool_catalog_summary(tools_by_server: dict[str, list[dict]]) -> str:
    lines: list[str] = ["## Available MCP Tool Servers\n"]
    for server_name, tools in sorted(tools_by_server.items()):
        tool_names = [t.get("name", "?") for t in tools]
        desc_parts = ", ".join(tool_names)
        lines.append(f"- **{server_name}** ({len(tools)} tools): {desc_parts}")
    return "\n".join(lines)
