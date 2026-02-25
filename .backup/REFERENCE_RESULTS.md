# Reference Results — Deterministic Risk Rating (before LLM risk rating change)

Run date: 2026-02-24, clean slate build

| Package | Affecting CVEs | Scanned | Risk (deterministic) |
|---------|---------------|---------|---------------------|
| requests==2.28.1 | 0 | 50 | LOW |
| flask==2.2.2 | 0 | 50 | LOW |
| django==4.2.0 | 43 | 50 | HIGH |
| urllib3==1.26.6 | 5 | 17 | HIGH |
| jinja2==3.0.3 | 3 | 37 | MEDIUM |
| pyyaml==5.4.1 | 0 | 6 | LOW |

Deterministic formula:
- 3+ affecting with critical/high severity → critical
- 2+ affecting → high
- 1 affecting → medium
- 0 → low

To revert:
  cp .backup/prompts.py.bak src/agent/prompts.py
  cp .backup/subagent.py.bak src/agent/subagent.py
