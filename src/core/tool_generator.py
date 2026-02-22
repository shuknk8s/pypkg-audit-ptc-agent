import json


class ToolGenerator:
    MCP_SERVERS_PATH = "/app/mcp_servers"

    def _generate_docs_for_tool(self, server_name: str, tool: dict) -> tuple[str, str]:
        tool_name = tool.get("name", "unknown")
        fn_name = tool_name.replace("-", "_").replace(".", "_")
        schema = tool.get("input_schema", {}) or {}
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        required = schema.get("required", []) if isinstance(schema, dict) else []
        lines = [
            f"# {server_name}.{tool_name}",
            "",
            "## Import",
            f"`from tools.{server_name} import {fn_name}`",
            "",
            "## Description",
            tool.get("description", "") or "(no description)",
            "",
            "## Parameters",
        ]
        if props:
            for prop_name, prop in props.items():
                ptype = (prop or {}).get("type", "any")
                preq = "required" if prop_name in required else "optional"
                pdesc = (prop or {}).get("description", "")
                lines.append(f"- `{prop_name}` ({ptype}, {preq}) - {pdesc}")
        else:
            lines.append("- none")
        return f"docs/{server_name}/{fn_name}.md", "\n".join(lines) + "\n"

    def _generate_tool_module(self, server_name: str, tools: list[dict]) -> str:
        lines = [
            '"""Auto-generated tool wrapper module."""',
            "from tools.mcp_client import call_tool",
            "",
        ]
        type_map = {
            "string": "str",
            "integer": "int",
            "boolean": "bool",
            "number": "float",
            "array": "list",
            "object": "dict",
        }
        for tool in tools:
            tool_name = tool.get("name", "unknown")
            fn_name = tool_name.replace("-", "_").replace(".", "_")
            schema = tool.get("input_schema", {}) or {}
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            required = set(schema.get("required", [])) if isinstance(schema, dict) else set()

            params: list[str] = []
            kwargs: list[str] = []
            for prop_name, prop in props.items():
                py_type = type_map.get((prop or {}).get("type", "string"), "str")
                if prop_name in required:
                    params.append(f"{prop_name}: {py_type}")
                else:
                    params.append(f"{prop_name}: {py_type} | None = None")
                kwargs.append(f'"{prop_name}": {prop_name}')
            if not params:
                params.append("**kwargs")
                call_args = "kwargs"
            else:
                call_args = "{" + ", ".join(kwargs) + "}"

            lines.extend(
                [
                    f"def {fn_name}({', '.join(params)}) -> dict:",
                    f'    """{tool.get("description", "")}"""',
                    f'    return call_tool("{server_name}", "{tool_name}", {call_args})',
                    "",
                ]
            )
        return "\n".join(lines).rstrip() + "\n"

    def _generate_mcp_client(self, server_configs: list[dict]) -> str:
        literal = json.dumps(server_configs, indent=2)
        return f'''"""Generated MCP client for sandbox tool wrappers."""
import atexit
import json
import subprocess
import os

SERVER_CONFIGS = {literal}
PROC_CACHE = {{}}


def _cleanup() -> None:
    for proc, _ in list(PROC_CACHE.values()):
        try:
            proc.kill()
            proc.wait(timeout=1)
        except Exception:
            pass


atexit.register(_cleanup)


def _send_request(proc, payload: dict) -> dict:
    proc.stdin.write((json.dumps(payload) + "\\n").encode())
    proc.stdin.flush()
    expected_id = payload.get("id")
    # Some MCP servers may emit non-JSON or notification lines on stdout.
    # Keep reading until we find a valid JSON-RPC response matching the request id.
    while True:
        line = proc.stdout.readline()
        if not line:
            return {{}}
        try:
            decoded = line.decode("utf-8", errors="replace").strip()
            if not decoded:
                continue
            msg = json.loads(decoded)
        except Exception:
            continue
        if not isinstance(msg, dict):
            continue
        if expected_id is not None and msg.get("id") != expected_id:
            # ignore notifications / responses for other requests
            continue
        return msg


def _get_server(server_name: str):
    if server_name in PROC_CACHE:
        proc, req_id = PROC_CACHE[server_name]
        if proc.poll() is None:
            return proc, req_id
    cfg = next((c for c in SERVER_CONFIGS if c.get("name") == server_name), None)
    if cfg is None:
        raise ValueError(f"Unknown server: {{server_name}}")

    env = {{**os.environ, **cfg.get("env", {{}})}}
    proc = subprocess.Popen(
        [cfg["command"]] + cfg.get("args", []),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    _send_request(
        proc,
        {{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {{"protocolVersion": "2024-11-05", "capabilities": {{}}, "clientInfo": {{"name": "ptc-v4", "version": "0.1"}}}},
        }},
    )
    proc.stdin.write((json.dumps({{"jsonrpc": "2.0", "method": "initialized", "params": {{}}}}) + "\\n").encode())
    proc.stdin.flush()
    PROC_CACHE[server_name] = (proc, 2)
    return proc, 2


def call_tool(server_name: str, tool_name: str, arguments: dict | None = None) -> dict:
    proc, req_id = _get_server(server_name)
    PROC_CACHE[server_name] = (proc, req_id + 1)
    payload = {{
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {{"name": tool_name, "arguments": arguments or {{}}}},
    }}
    response = _send_request(proc, payload)
    if "error" in response:
        raise RuntimeError(str(response["error"]))
    return response.get("result", {{}})
'''

    def generate_all(
        self,
        tools_by_server: dict[str, list[dict]],
        server_configs: list[dict],
    ) -> dict[str, str]:
        files: dict[str, str] = {"mcp_client.py": self._generate_mcp_client(server_configs)}
        for server_name, tools in tools_by_server.items():
            safe_name = server_name.replace("-", "_")
            files[f"{safe_name}.py"] = self._generate_tool_module(safe_name, tools)
            for tool in tools:
                doc_name, doc_content = self._generate_docs_for_tool(safe_name, tool)
                files[doc_name] = doc_content
        return files
