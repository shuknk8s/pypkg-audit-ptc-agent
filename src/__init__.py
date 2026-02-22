import sys


if "prog_tool_call_demo" in sys.modules:
    raise ImportError(
        "ptc-v4-dep-gap is isolated and must not import from parent prog-tool-call-demo"
    )
