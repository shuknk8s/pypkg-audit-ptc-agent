import asyncio
import io
import os
import tarfile
from typing import TYPE_CHECKING

import docker.errors
from deepagents.backends.protocol import (
    EditResult,
    ExecuteResponse,
    FileDownloadResponse,
    FileUploadResponse,
    SandboxBackendProtocol,
    WriteResult,
)

if TYPE_CHECKING:
    from src.sandbox.docker_sandbox import DockerSandbox


def _make_tar(filename: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=filename)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    buf.seek(0)
    return buf.read()


class DockerBackend(SandboxBackendProtocol):
    def __init__(self, sandbox: "DockerSandbox", root_dir: str = "/app"):
        self.sandbox = sandbox
        self.root_dir = root_dir.rstrip("/")

    @property
    def id(self) -> str:
        return self.sandbox.container_name

    @property
    def container(self):
        return self.sandbox.container

    def _normalize_path(self, path: str) -> str:
        if not path or path == ".":
            return self.root_dir
        if os.path.isabs(path):
            return path
        return f"{self.root_dir}/{path}"

    def execute(self, command: str) -> ExecuteResponse:
        return self.sandbox.execute(command)

    def read(self, file_path: str, offset: int = 0, limit: int = 2000) -> str:
        abs_path = self._normalize_path(file_path)
        try:
            tar_stream, _ = self.container.get_archive(abs_path)
            buf = io.BytesIO()
            for chunk in tar_stream:
                buf.write(chunk)
            buf.seek(0)
            with tarfile.open(fileobj=buf) as tar:
                member = tar.getmembers()[0]
                file_like = tar.extractfile(member)
                if file_like is None:
                    return f"Error: '{file_path}' is not a regular file"
                content = file_like.read().decode("utf-8", errors="replace")
            lines = content.splitlines()
            window = lines[offset : offset + limit]
            return "\n".join(f"{offset + i + 1:6}\t{line}" for i, line in enumerate(window))
        except docker.errors.NotFound:
            return f"Error: File '{file_path}' not found"

    def write(self, file_path: str, content: str) -> WriteResult:
        abs_path = self._normalize_path(file_path)
        parent_dir = os.path.dirname(abs_path)
        filename = os.path.basename(abs_path)
        self.container.exec_run(["sh", "-c", f"mkdir -p {parent_dir}"])
        self.container.put_archive(parent_dir, _make_tar(filename, content.encode("utf-8")))
        return WriteResult(path=abs_path)

    def edit(
        self,
        file_path: str,
        old_string: str,
        new_string: str,
        *,
        replace_all: bool = False,
    ) -> EditResult:
        abs_path = self._normalize_path(file_path)
        try:
            tar_stream, _ = self.container.get_archive(abs_path)
            buf = io.BytesIO()
            for chunk in tar_stream:
                buf.write(chunk)
            buf.seek(0)
            with tarfile.open(fileobj=buf) as tar:
                member = tar.getmembers()[0]
                file_like = tar.extractfile(member)
                if file_like is None:
                    return EditResult(error=f"File '{file_path}' is not a regular file")
                raw = file_like.read().decode("utf-8", errors="replace")
        except docker.errors.NotFound:
            return EditResult(error=f"File '{file_path}' not found")

        if replace_all:
            updated = raw.replace(old_string, new_string)
        else:
            updated = raw.replace(old_string, new_string, 1)
        self.write(file_path, updated)
        return EditResult(path=abs_path)

    def glob_info(self, pattern: str, path: str = "/") -> list[dict]:
        result = self.container.exec_run(
            ["sh", "-c", f"find {path} -path '{pattern}' -type f 2>/dev/null"],
            workdir=self.root_dir,
        )
        output = result.output.decode("utf-8", errors="replace").strip()
        if not output:
            return []
        return [{"path": p} for p in output.splitlines()]

    def grep_raw(
        self, pattern: str, path: str | None = None, glob: str | None = None
    ) -> list[dict] | str:
        search_path = path or self.root_dir
        glob_arg = f"--glob '{glob}'" if glob else ""
        cmd = f"rg --json {glob_arg} '{pattern}' {search_path} 2>/dev/null"
        result = self.container.exec_run(["sh", "-c", cmd], workdir=self.root_dir)
        return result.output.decode("utf-8", errors="replace")

    def upload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        responses: list[FileUploadResponse] = []
        for dest_path, content in files:
            abs_path = self._normalize_path(dest_path)
            parent_dir = os.path.dirname(abs_path)
            filename = os.path.basename(abs_path)
            self.container.exec_run(["sh", "-c", f"mkdir -p {parent_dir}"])
            self.container.put_archive(parent_dir, _make_tar(filename, content))
            responses.append(FileUploadResponse(path=abs_path))
        return responses

    def download_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        responses: list[FileDownloadResponse] = []
        for file_path in paths:
            abs_path = self._normalize_path(file_path)
            try:
                tar_stream, _ = self.container.get_archive(abs_path)
                buf = io.BytesIO()
                for chunk in tar_stream:
                    buf.write(chunk)
                buf.seek(0)
                with tarfile.open(fileobj=buf) as tar:
                    member = tar.getmembers()[0]
                    file_like = tar.extractfile(member)
                    if file_like is None:
                        responses.append(
                            FileDownloadResponse(
                                path=abs_path,
                                content=b"",
                                error=f"File '{file_path}' is not a regular file",
                            )
                        )
                        continue
                    content = file_like.read()
                responses.append(FileDownloadResponse(path=abs_path, content=content))
            except docker.errors.NotFound:
                responses.append(
                    FileDownloadResponse(path=abs_path, content=b"", error=f"File '{file_path}' not found")
                )
        return responses

    async def als_info(self, path: str = ".") -> list[dict]:
        return await asyncio.to_thread(self.ls_info, path)

    async def aread(self, file_path: str, offset: int = 0, limit: int = 2000) -> str:
        return await asyncio.to_thread(self.read, file_path, offset, limit)

    async def awrite(self, file_path: str, content: str):
        return await asyncio.to_thread(self.write, file_path, content)

    async def aedit(
        self,
        file_path: str,
        old_string: str,
        new_string: str,
        *,
        replace_all: bool = False,
    ):
        return await asyncio.to_thread(
            self.edit, file_path, old_string, new_string, replace_all=replace_all
        )

    async def aglob_info(self, pattern: str, path: str = "/") -> list[dict]:
        return await asyncio.to_thread(self.glob_info, pattern, path)

    async def agrep_raw(
        self, pattern: str, path: str | None = None, glob: str | None = None
    ) -> list[dict] | str:
        return await asyncio.to_thread(self.grep_raw, pattern, path, glob)

    async def aupload_files(self, files: list[tuple[str, bytes]]) -> list:
        return await asyncio.to_thread(self.upload_files, files)

    async def adownload_files(self, paths: list[str]) -> list:
        return await asyncio.to_thread(self.download_files, paths)

    async def aexecute(self, command: str):
        return await asyncio.to_thread(self.execute, command)

    def ls_info(self, path: str = ".") -> list[dict]:
        abs_path = self._normalize_path(path)
        result = self.container.exec_run(
            ["sh", "-c", f"ls -la {abs_path} 2>/dev/null"],
            workdir=self.root_dir,
        )
        output = result.output.decode("utf-8", errors="replace").strip()
        entries: list[dict] = []
        for line in output.splitlines()[1:]:
            parts = line.split(None, 8)
            if len(parts) >= 9:
                entries.append(
                    {
                        "name": parts[8],
                        "type": "dir" if line.startswith("d") else "file",
                    }
                )
        return entries
