"""This module intentionally contains no LangChain @tool wrappers.

PTC (Programmatic Tool Calls) requires that tool calls happen INSIDE the Docker
sandbox via LLM-generated Python scripts, not via LangChain @tool decorators
called directly by the LLM.

Tool wrappers are generated at runtime by src/core/tool_generator.ToolGenerator
and uploaded to /app/tools/ inside the container. The LLM writes scripts that
import those wrappers (from tools.nvd, tools.pypi, tools.github_api) and
execute them inside the container.

PTD doc files are generated alongside the wrappers and uploaded to
/app/tools/docs/<server>/<tool>.md inside the container. The LLM-generated
scripts read these files with open() before calling each tool.

See src/agent/prompts.py and src/agent/subagent.py for the full PTC+PTD design.
"""
