import re


_PIN_PATTERN = re.compile(r"^\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)\s*$")


def parse_requirements_input(requirements_input: str | list[str]) -> list[dict]:
    if isinstance(requirements_input, list):
        lines = requirements_input
    else:
        lines = requirements_input.splitlines()

    specs: list[dict] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _PIN_PATTERN.match(line)
        if not match:
            continue
        specs.append(
            {
                "package": match.group(1),
                "pinned_version": match.group(2),
            }
        )
    if not specs:
        raise ValueError("No pinned package specs found. Expected lines like package==version")
    return specs
