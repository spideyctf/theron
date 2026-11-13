# Operational repair verification

The original final-code evaluation and failed live smoke remain attached to detector `4c166e0b179e1ff10a3a432e2bd439765b601a81`. Their outcomes were committed as `1043ed4` before scanner changes. The subsequent one-condition crash fix is `cfbfb83db97e468035a23c7ad19c0597bb46c317`. [Repair declaration](LIVE-REPAIR.md), [original crash](live-selfscan-failure.json), [repaired live receipt](live-selfscan-repaired.json).

## Change and regression evidence

A quote-membership check on an unsupported computed expression could create a `None` state key and crash analysis. Only a resolvable target now qualifies for that guard; arbitrary calls do not receive a guessed safety boundary. Original controls for both `in` and `not in` fail before the fix, pass after it, and retain a real external-input command sink. The full suite passes **558 Python tests**, with one existing dependency deprecation warning. Frontend tests remain **13 passing**, with TypeScript and production build passing.

All **1,470 exposed synthetic variant outcomes and alert counts** are identical to the prior published results. [Canonical per-case digest comparison](post-repair-regressions.json). OWASP exposed test remains TP65/FN24/FP0/TN156 (73.03% recall, 100% label-matched precision); PySASTBench remains TP93/FN26/FP4/TN116 with one unresolved label (78.15% recall, 95.88% precision). This replay is a regression check, not another untouched evaluation. The nine-case adverse result remains an observation at the original detector, not a held-out score for the repaired implementation.

## Actual live transport smoke

One completed scan of public `spideyctf/theron`, target commit `4c166e0`, using repaired detector `cfbfb83`:

| Measure | Observed |
| --- | ---: |
| Modules completed | SAST, agentic, AI, SCA |
| Files selected / fetched / scanned | 273 / 273 / 273 |
| Wall time | 168.19 seconds |
| Peak process working set | 103.94 MiB |
| Application non-informational alerts | 0 |
| Application informational coverage notices | 3 |
| Context findings | 20 |
| SBOM components / unresolved versions | 151 / 15 |
| Network responses | 412 HTTP200 |
| GitHub API / raw file / OSV responses | 3 / 273 / 136 |
| JSON / HTML / SARIF bytes | 118361 / 112496 / 32510 |

The three application notices are unresolved tuple mapping in `scanner/cli.py`, analysis budget exhaustion in `scanner/python_analysis.py`, and unresolved dependency declarations in `pyproject.toml`. **Zero non-informational alerts is not proof that the repository is clean. Analysis coverage is incomplete.** Context findings were not independently validated as vulnerabilities. A working SBOM is not its own completeness oracle. OSV data is live and can change; receipt status/body hashes preserve this observation, not a permanent advisory truth.

No token/headers were stored. No target code, setup script, exploit, MCP command or application/browser/server ran. The only network traffic measured was static GitHub retrieval and advisory lookup. Exports are retained in the ignored `.benchmark-cache/final-realcode/live-selfscan-repaired.{json,html,sarif}`. The public compact receipt preserves classifications, locations, fingerprints, network metadata and export hashes without redistributing source snippets.

The first crashed harness did not preserve network metadata; that absence remains recorded. The revised harness preserves redacted network/frame metadata on failure. The completed live scan does not erase the original failure or establish multiuser capacity, durable history, operational SLAs or detection accuracy.

## Reproduce the operational repair

From the repaired checkout with web/development dependencies:

```powershell
.venv\Scripts\python.exe -m pytest tests -q
.venv\Scripts\python.exe -m scripts.verify_operational_repair
# Uses the configured gh account; refuses any account except spideyctf.
.venv\Scripts\python.exe -u -m scripts.live_operational_smoke --implementation cfbfb83db97e468035a23c7ad19c0597bb46c317
```

The live target stays pinned to `4c166e0`; the implementation freeze differs deliberately. Never reuse the final nine cases as unseen evidence after detector changes. Independent human alert/source review and a fresh evaluation remain research gates.
