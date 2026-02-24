from pydantic import BaseModel, Field


class DockerConfig(BaseModel):
    image: str = "pypkg-audit-ptc-agent:latest"
    container_name: str = "pypkg-audit-ptc-agent-sandbox"
    auto_remove: bool = False
    network_mode: str = "bridge"


class MCPServerConfig(BaseModel):
    name: str
    description: str = ""
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    tool_exposure_mode: str = "summary"


class MCPConfig(BaseModel):
    servers: list[MCPServerConfig] = Field(default_factory=list)
    tool_discovery_enabled: bool = True
    lazy_load: bool = True
    tool_exposure_mode: str = "summary"


class RuntimeConfig(BaseModel):
    max_run_seconds: int = 240
    quality_report_enabled: bool = True


class LLMConfig(BaseModel):
    model: str = "gpt-4o-mini"
    temperature: float = 0.0
    max_tokens: int = 4096
    seed: int = 42
    top_p: float = 1.0


class CoreConfig(BaseModel):
    docker: DockerConfig = Field(default_factory=DockerConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
