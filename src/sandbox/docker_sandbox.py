"""DockerSandbox — implements SandboxBackendProtocol directly.

Follows the official deepagents custom-backend pattern:
  class DockerSandbox(SandboxBackendProtocol):
      def __init__(self, ...):
          self.container = docker_client.containers.run(...)  # starts in __init__
      def execute(self, command) -> ExecuteResponse: ...
      # + all BackendProtocol filesystem methods

Passed directly to create_deep_agent(backend=sandbox).
No separate wrapper class needed.
"""
from __future__ import annotations

import asyncio
import io
import os
import re
import tarfile
import uuid

import docker
import docker.errors
from deepagents.backends.protocol import (
    EditResult,
    ExecuteResponse,
    FileDownloadResponse,
    FileUploadResponse,
    SandboxBackendProtocol,
    WriteResult,
)
from dotenv import load_dotenv

load_dotenv(override=True)


def _make_tar(filename: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=filename)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    buf.seek(0)
    return buf.read()


class DockerSandbox(SandboxBackendProtocol):
    """Docker-backed sandbox — one container per instance.

    Container starts synchronously in __init__ so it's immediately available.
    Each instance has its own unique container, enabling external parallelism
    via asyncio.gather() across multiple DockerSandbox instances.
    """

    def __init__(
        self,
        image: str = "dep-audit-deepagent:latest",
        container_name: str | None = None,
        root_dir: str = "/app",
    ) -> None:
        self.image = image
        self.container_name = container_name or f"dep-audit-{uuid.uuid4().hex[:8]}"
        self.root_dir = root_dir.rstrip("/")
        self._sandbox_id = self.container_name

        self.client = docker.from_env()

        # Remove any existing container with this name
        try:
            existing = self.client.containers.get(self.container_name)
            existing.remove(force=True)
        except docker.errors.NotFound:
            pass

        # Start container — persistent, kept alive for agent's full turn
        self.container = self.client.containers.run(
            self.image,
            ["tail", "-f", "/dev/null"],
            detach=True,
            tty=True,
            name=self.container_name,
        )

        # Create standard working directories
        self.container.exec_run(
            ["sh", "-c",
             "mkdir -p /app/tools /app/tools/docs /app/code /app/results /app/mcp_servers"]
        )

    # ------------------------------------------------------------------
    # SandboxBackendProtocol — required
    # ------------------------------------------------------------------

    @property
    def id(self) -> str:
        return self._sandbox_id

    def _exec_env(self) -> dict[str, str]:
        env: dict[str, str] = {
            "PYTHONPATH": "/app",
            "VIRTUAL_ENV": "/app/.venv",
            "PATH": "/app/.venv/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
        for key, value in os.environ.items():
            if key.endswith("_API_KEY") or key.endswith("_TOKEN"):
                env[key] = value
        return env

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
    def _summarize(text: str, max_lines: int = 120, max_chars: int = 4000) -> tuple[str, bool]:
        if not text:
            return "", False
        truncated = False
        lines = text.splitlines()
        if len(lines) > max_lines:
            head, tail = lines[:70], lines[-30:]
            text = "\n".join(head + [f"... [{len(lines)-100} lines omitted] ..."] + tail)
            truncated = True
        if len(text) > max_chars:
            text = f"{text[:2600]}\n...[truncated]...\n{text[-1100:]}"
            truncated = True
        return text, truncated

    def execute(self, command: str) -> ExecuteResponse:
        command = self._strip_code_fences(command)
        result = self.container.exec_run(
            cmd=["sh", "-c", command],
            environment=self._exec_env(),
            workdir=self.root_dir,
            demux=True,
        )
        stdout = (result.output[0] or b"").decode("utf-8", errors="replace")
        stderr = (result.output[1] or b"").decode("utf-8", errors="replace")
        exit_code = result.exit_code

        output = stdout
        if exit_code != 0 and not stdout.strip() and stderr.strip():
            output = f"[exit_code={exit_code}]\n[stderr]\n{stderr[:800]}"

        # Preserve PTC marker fully — never truncate it
        if "__PTC_JSON_B64__" in output:
            return ExecuteResponse(output=output, exit_code=exit_code, truncated=False)

        output, truncated = self._summarize(output)
        return ExecuteResponse(output=output, exit_code=exit_code, truncated=truncated)

    # aexecute is inherited from SandboxBackendProtocol — it handles timeout kwarg correctly

    # ------------------------------------------------------------------
    # BackendProtocol filesystem — all operations via Docker API
    # ------------------------------------------------------------------

    def _abs(self, path: str) -> str:
        if not path or path == ".":
            return self.root_dir
        return path if os.path.isabs(path) else f"{self.root_dir}/{path}"

    def read(self, file_path: str, offset: int = 0, limit: int = 2000) -> str:
        abs_path = self._abs(file_path)
        try:
            tar_stream, _ = self.container.get_archive(abs_path)
            buf = io.BytesIO()
            for chunk in tar_stream:
                buf.write(chunk)
            buf.seek(0)
            with tarfile.open(fileobj=buf) as tar:
                f = tar.extractfile(tar.getmembers()[0])
                if f is None:
                    return f"Error: '{file_path}' is not a regular file"
                content = f.read().decode("utf-8", errors="replace")
            lines = content.splitlines()
            window = lines[offset: offset + limit]
            return "\n".join(f"{offset + i + 1:6}\t{line}" for i, line in enumerate(window))
        except docker.errors.NotFound:
            return f"Error: File '{file_path}' not found"

    def write(self, file_path: str, content: str) -> WriteResult:
        abs_path = self._abs(file_path)
        parent = os.path.dirname(abs_path)
        self.container.exec_run(["sh", "-c", f"mkdir -p {parent}"])
        self.container.put_archive(parent, _make_tar(os.path.basename(abs_path), content.encode("utf-8")))
        return WriteResult(path=abs_path)

    def edit(self, file_path: str, old_string: str, new_string: str, *, replace_all: bool = False) -> EditResult:
        abs_path = self._abs(file_path)
        try:
            tar_stream, _ = self.container.get_archive(abs_path)
            buf = io.BytesIO()
            for chunk in tar_stream:
                buf.write(chunk)
            buf.seek(0)
            with tarfile.open(fileobj=buf) as tar:
                f = tar.extractfile(tar.getmembers()[0])
                if f is None:
                    return EditResult(error=f"File '{file_path}' is not a regular file")
                raw = f.read().decode("utf-8", errors="replace")
        except docker.errors.NotFound:
            return EditResult(error=f"File '{file_path}' not found")
        updated = raw.replace(old_string, new_string) if replace_all else raw.replace(old_string, new_string, 1)
        self.write(file_path, updated)
        return EditResult(path=abs_path)

    def ls_info(self, path: str = ".") -> list[dict]:
        abs_path = self._abs(path)
        result = self.container.exec_run(
            ["sh", "-c", f"ls -la {abs_path} 2>/dev/null"],
            workdir=self.root_dir,
        )
        output = result.output.decode("utf-8", errors="replace").strip()
        entries: list[dict] = []
        for line in output.splitlines()[1:]:
            parts = line.split(None, 8)
            if len(parts) >= 9:
                entries.append({"name": parts[8], "type": "dir" if line.startswith("d") else "file"})
        return entries

    def glob_info(self, pattern: str, path: str = "/") -> list[dict]:
        result = self.container.exec_run(
            ["sh", "-c", f"find {path} -path '{pattern}' -type f 2>/dev/null"],
            workdir=self.root_dir,
        )
        output = result.output.decode("utf-8", errors="replace").strip()
        return [{"path": p} for p in output.splitlines()] if output else []

    def grep_raw(self, pattern: str, path: str | None = None, glob: str | None = None) -> list[dict] | str:
        search_path = path or self.root_dir
        glob_arg = f"--glob '{glob}'" if glob else ""
        result = self.container.exec_run(
            ["sh", "-c", f"rg --json {glob_arg} '{pattern}' {search_path} 2>/dev/null"],
            workdir=self.root_dir,
        )
        return result.output.decode("utf-8", errors="replace")

    def upload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        responses: list[FileUploadResponse] = []
        for dest_path, content in files:
            abs_path = self._abs(dest_path)
            parent = os.path.dirname(abs_path)
            self.container.exec_run(["sh", "-c", f"mkdir -p {parent}"])
            self.container.put_archive(parent, _make_tar(os.path.basename(abs_path), content))
            responses.append(FileUploadResponse(path=abs_path))
        return responses

    def download_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        responses: list[FileDownloadResponse] = []
        for file_path in paths:
            abs_path = self._abs(file_path)
            try:
                tar_stream, _ = self.container.get_archive(abs_path)
                buf = io.BytesIO()
                for chunk in tar_stream:
                    buf.write(chunk)
                buf.seek(0)
                with tarfile.open(fileobj=buf) as tar:
                    f = tar.extractfile(tar.getmembers()[0])
                    content = f.read() if f else b""
                responses.append(FileDownloadResponse(path=abs_path, content=content))
            except docker.errors.NotFound:
                responses.append(FileDownloadResponse(path=abs_path, content=b"", error=f"Not found: {file_path}"))
        return responses

    # Async wrappers
    async def aread(self, file_path: str, offset: int = 0, limit: int = 2000) -> str:
        return await asyncio.to_thread(self.read, file_path, offset, limit)

    async def awrite(self, file_path: str, content: str) -> WriteResult:
        return await asyncio.to_thread(self.write, file_path, content)

    async def aedit(self, file_path: str, old_string: str, new_string: str, *, replace_all: bool = False) -> EditResult:
        return await asyncio.to_thread(self.edit, file_path, old_string, new_string, replace_all=replace_all)

    async def als_info(self, path: str = ".") -> list[dict]:
        return await asyncio.to_thread(self.ls_info, path)

    async def aglob_info(self, pattern: str, path: str = "/") -> list[dict]:
        return await asyncio.to_thread(self.glob_info, pattern, path)

    async def agrep_raw(self, pattern: str, path: str | None = None, glob: str | None = None) -> list[dict] | str:
        return await asyncio.to_thread(self.grep_raw, pattern, path, glob)

    async def aupload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        return await asyncio.to_thread(self.upload_files, files)

    async def adownload_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        return await asyncio.to_thread(self.download_files, paths)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def stop(self) -> None:
        if self.container is None:
            return
        try:
            self.container.stop()
            self.container.remove()
        except docker.errors.NotFound:
            pass
        self.container = None

    def __enter__(self) -> "DockerSandbox":
        return self

    def __exit__(self, *_) -> bool:
        self.stop()
        return False
