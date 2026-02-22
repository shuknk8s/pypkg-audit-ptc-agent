import asyncio
import os

import structlog
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from src.config.core import MCPServerConfig

logger = structlog.get_logger()


class MCPServerConnection:
    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.tools: list[dict] = []
        self.connected = False
        self._disconnect_event: asyncio.Event | None = None
        self._task: asyncio.Task | None = None

    def _prepare_env(self) -> dict[str, str]:
        env = dict(os.environ)
        for key, value in self.config.env.items():
            if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                env[key] = os.environ.get(value[2:-1], "")
            else:
                env[key] = value
        env.setdefault("NO_COLOR", "1")
        return env

    async def connect(self) -> None:
        server_params = StdioServerParameters(
            command=self.config.command,
            args=self.config.args,
            env=self._prepare_env(),
        )
        self._disconnect_event = asyncio.Event()

        async def _run() -> None:
            with open(os.devnull, "w", encoding="utf-8") as errlog:
                async with stdio_client(server_params, errlog=errlog) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()
                        tool_result = await session.list_tools()
                        self.tools = [
                            {
                                "name": tool.name,
                                "description": tool.description or "",
                                "input_schema": tool.inputSchema or {},
                                "server": self.config.name,
                            }
                            for tool in tool_result.tools
                        ]
                        self.connected = True
                        logger.info("mcp_connected", server=self.config.name, tools=len(self.tools))
                        await self._disconnect_event.wait()

        self._task = asyncio.create_task(_run())

    async def disconnect(self) -> None:
        if self._disconnect_event is not None:
            self._disconnect_event.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=3.0)
            except (asyncio.TimeoutError, Exception):
                pass
        self.connected = False


class MCPRegistry:
    def __init__(self, server_configs: list[MCPServerConfig]):
        self.server_configs = server_configs
        self.connections: list[MCPServerConnection] = []

    async def connect_all(self) -> None:
        self.connections = [MCPServerConnection(cfg) for cfg in self.server_configs]
        await asyncio.gather(*[conn.connect() for conn in self.connections], return_exceptions=True)

        deadline = asyncio.get_running_loop().time() + 15.0
        while asyncio.get_running_loop().time() < deadline:
            if all(conn.connected for conn in self.connections):
                break
            await asyncio.sleep(0.1)

    async def disconnect_all(self) -> None:
        await asyncio.gather(*[conn.disconnect() for conn in self.connections], return_exceptions=True)

    def get_tools(self) -> list[dict]:
        all_tools: list[dict] = []
        for conn in self.connections:
            all_tools.extend(conn.tools)
        return all_tools

    def get_tools_by_server(self) -> dict[str, list[dict]]:
        return {conn.config.name: conn.tools for conn in self.connections}

    async def __aenter__(self):
        await self.connect_all()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect_all()
        return False
