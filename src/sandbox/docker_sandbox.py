import os
import re

import docker
import docker.errors
from deepagents.backends.protocol import ExecuteResponse
from dotenv import load_dotenv

load_dotenv(override=True)


class DockerSandbox:
    def __init__(
        self,
        image: str = "ptc-v4-dep-gap:latest",
        container_name: str = "ptc-v4-dep-gap-sandbox",
    ) -> None:
        self.image = image
        self.container_name = container_name
        self.client = docker.from_env()
        self.container = None

    def start(self) -> None:
        try:
            existing = self.client.containers.get(self.container_name)
            existing.remove(force=True)
        except docker.errors.NotFound:
            pass

        self.container = self.client.containers.run(
            self.image,
            ["tail", "-f", "/dev/null"],
            detach=True,
            name=self.container_name,
        )
        self.container.exec_run(
            [
                "sh",
                "-c",
                "mkdir -p /app/tools /app/tools/docs /app/code /app/results /app/data /app/mcp_servers",
            ]
        )

    def stop(self) -> None:
        if self.container is None:
            return
        try:
            self.container.stop()
            self.container.remove()
        except docker.errors.NotFound:
            pass
        self.container = None

    def _get_exec_env(self) -> dict[str, str]:
        env: dict[str, str] = {
            "PYTHONPATH": "/app",
            "VIRTUAL_ENV": "/app/.venv",
            "PATH": "/app/.venv/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
        for key, value in os.environ.items():
            if key.endswith("_API_KEY") or key.endswith("_TOKEN"):
                env[key] = value
        return env

    def _detect_missing_imports(self, stderr: str) -> list[str]:
        patterns = [
            r"ModuleNotFoundError: No module named '([^']+)'",
            r"ImportError: No module named '([^']+)'",
        ]
        matches: list[str] = []
        for pattern in patterns:
            matches.extend(re.findall(pattern, stderr))
        return list({m.split(".")[0] for m in matches})

    @staticmethod
    def _strip_code_fences(command: str) -> str:
        stripped = command.strip()
        if not stripped.startswith("```"):
            return command
        lines = stripped.split("\n")[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines)

    @staticmethod
    def _summarize_output(text: str, *, max_lines: int = 120, max_chars: int = 4000) -> tuple[str, bool]:
        if not text:
            return "", False
        summarized = False
        lines = text.splitlines()
        if len(lines) > max_lines:
            head = lines[:70]
            tail = lines[-30:]
            omitted = len(lines) - len(head) - len(tail)
            text = "\n".join(head + [f"... [{omitted} lines omitted] ..."] + tail)
            summarized = True
        if len(text) > max_chars:
            text = f"{text[:2600]}\n... [output truncated] ...\n{text[-1100:]}"
            summarized = True
        return text, summarized

    def execute(self, command: str, max_retries: int = 1) -> ExecuteResponse:
        if self.container is None:
            raise RuntimeError("Sandbox not started")
        command = self._strip_code_fences(command)
        env = self._get_exec_env()

        attempt = 0
        while attempt <= max_retries:
            result = self.container.exec_run(
                cmd=["sh", "-c", command],
                environment=env,
                workdir="/app",
                demux=True,
            )
            stdout = (result.output[0] or b"").decode("utf-8", errors="replace")
            stderr = (result.output[1] or b"").decode("utf-8", errors="replace")
            exit_code = result.exit_code

            if exit_code != 0 and attempt < max_retries:
                missing = self._detect_missing_imports(stderr)
                if missing:
                    for pkg in missing:
                        self.container.exec_run(
                            cmd=["sh", "-c", f"uv add {pkg}"],
                            environment=env,
                            workdir="/app",
                        )
                    attempt += 1
                    continue

            output = stdout
            if exit_code != 0 and not stdout.strip() and stderr.strip():
                output = f"[exit_code={exit_code}]\n[stderr]\n{stderr[:800]}"
            # Preserve full payload for PTC structured output markers.
            if "__PTC_JSON_B64__" in output:
                summarized = False
            else:
                output, summarized = self._summarize_output(output)
            return ExecuteResponse(output=output, exit_code=exit_code, truncated=summarized)

        return ExecuteResponse(output="", exit_code=-1, truncated=False)

    def __enter__(self) -> "DockerSandbox":
        self.start()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> bool:
        self.stop()
        return False
