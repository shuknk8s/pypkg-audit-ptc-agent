import base64
import binascii
import json
import os
import re
from pathlib import Path


def _parse_json_stdout(stdout: str) -> dict:
    raw_text = stdout or ""
    cleaned = "".join(ch for ch in raw_text if ch in "\n\t" or ord(ch) >= 32)
    text = cleaned.strip()
    if not text:
        raise ValueError("Script output is empty")
    for line in reversed(text.splitlines()):
        if "__PTC_JSON_B64__" in line:
            tail = line.split("__PTC_JSON_B64__", 1)[1].strip()
            m = re.match(r"^([A-Za-z0-9+/=]+)", tail)
            if not m:
                continue
            encoded = m.group(1)
            try:
                decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
                return json.loads(decoded)
            except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
                continue
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        for line in reversed(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            if line.startswith("{") and line.endswith("}"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    pass
            s = line.find("{")
            e = line.rfind("}")
            if s != -1 and e != -1 and e > s:
                try:
                    return json.loads(line[s : e + 1])
                except json.JSONDecodeError:
                    continue
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("Script output does not contain valid JSON object")
        return json.loads(text[start : end + 1])


def _container_server_configs(config_servers: list) -> list[dict]:
    container_configs: list[dict] = []
    for server in config_servers:
        cfg = server.model_dump()
        args = cfg.get("args", [])
        module_name = None
        if "-m" in args:
            idx = args.index("-m")
            if idx + 1 < len(args):
                module_name = args[idx + 1]
        if module_name and module_name.startswith("src.mcp_servers."):
            script_name = f"{module_name.split('.')[-1]}.py"
            cfg["command"] = "python3"
            cfg["args"] = [f"/app/mcp_servers/{script_name}"]
        # Resolve ${VAR} placeholders so the generated mcp_client.py gets
        # actual values instead of literal placeholder strings.
        resolved_env: dict[str, str] = {}
        for key, value in (cfg.get("env") or {}).items():
            if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                resolved_env[key] = os.environ.get(value[2:-1], "")
            else:
                resolved_env[key] = str(value)
        cfg["env"] = resolved_env
        container_configs.append(cfg)
    return container_configs


def _mcp_server_uploads(config_servers: list) -> list[tuple[str, bytes]]:
    uploads: list[tuple[str, bytes]] = []
    repo_root = Path(__file__).resolve().parents[2]
    for server in config_servers:
        args = server.args
        module_name = None
        if "-m" in args:
            idx = args.index("-m")
            if idx + 1 < len(args):
                module_name = args[idx + 1]
        if module_name and module_name.startswith("src.mcp_servers."):
            module_rel_path = module_name.replace(".", "/") + ".py"
            source_path = repo_root / module_rel_path
            content = source_path.read_text(encoding="utf-8")
            script_name = f"{module_name.split('.')[-1]}.py"
            uploads.append((f"/app/mcp_servers/{script_name}", content.encode("utf-8")))
    return uploads
