# Security-state checks, dependency evidence and upstream validation

**Latest follow-up:** [precision fixes, TLS hostname state and all ten pilot execution receipts](FOLLOWUP.md), detector `7b64719`, 763 Python tests passing. Ten selected behavior pairs distinguish revisions: five upstream, two adapted upstream and three author-derived. SQLparse/OctoPrint adapter observations do not replace their original upstream/application validation; CVAT remains unverified. The original checkpoint below is retained as historical evidence.

14 November 2026. Detector frozen at `f370de1c7078e2b6e07154e2a8d4974ef757e3b1`. This is local development and isolated verification of public, pinned source; no deployed targets or credentials are probed. [Plan and acceptance gates](PLAN.md).

## Current results

| Check | Result | Limit |
| --- | --- | --- |
| Regression | 746 Python tests; 17 frontend tests; production frontend build pass | Tested engineering behavior, not publication readiness |
| Exposed synthetic replay | All 1,470 case outcomes and alert counts unchanged | OWASP test recall 73.03%, label precision 100%; PySASTBench recall 78.15%, precision 95.88%; these corpora have been used for tuning |
| Six exposed mechanisms | 5/6 vulnerable cases, no repaired-unit candidates; strict CNA matches 2/5 labelled cases | Source-guided; CVAT remains missed |
| Ten exposed pilot mechanisms | 4/10 vulnerable cases, no repaired-unit candidates; strict CNA matches 2/8 labelled cases | Source-guided, not new holdout recall; Requests retains the original project-alias overlap; two CNA labels absent |
| MCP SDK paired upstream tests | Vulnerable security: 4 failures; fixed security: 4 passes; functional: 4 passes on each revision | Two selected security and two selected functional tests, each on asyncio/trio; not the full SDK suite |
| Pymdown paired upstream tests | Security fails before repair and passes after; one functional test passes on both | Selected upstream path-boundary tests; scanner still misses this mechanism |
| SQLparse upstream execution | Each revision: 427 functional passes, 3 expected failures; patch regression passes on both | Functional validation only; patch test does not demonstrate resource-exhaustion security behavior |
| Live OSV | 134 completed unique version queries, no advisory matches; one unresolved-range coverage notice | Declared versions, not installed/deployed inventories or vulnerable-function reachability |
| Correlation controls | 13/13 original controls correct; 4 inferred context edges; vulnerability payloads unchanged | Zero new vulnerability discoveries; no real-code edge accuracy or review benefit measured |
| Offline operational smoke | 53.94 seconds / 120-second limit; 273 files read from 275 selected; SAST/AI/agentic complete | One workload; three application coverage notices, 12 context findings and two oversized inputs retained |

## What changed

Four bounded advisory models inspect compatibility normalization after HTML cleaning, certificate policy mutated after shared pool selection, uncaught per-message MCP validation, and raw callable access in AST interpreters. Evidence includes required conditions, exact action locations and library/caller assumptions. They do not establish general sanitizer, TLS, authorization or sandbox correctness.

OSV queries consume pagination with a bounded page limit, reject incomplete/malformed responses without caching partial answers, and carry package/version/ecosystem, manifest, advisory identifiers, CWE metadata, fixed boundaries and lookup time through JSON/API/SARIF/HTML/frontend. OSV's public query API needs no secret key. Fixed boundaries are upstream advisory data, not a guarantee that an upgrade is compatible or fixes every advisory.

MCP context can join a supported Python entrypoint's top-level same-spelling import to an exact OSV dependency declaration in the nearest supported manifest. Local shadowing, namespaces, conditional imports, standard-library imports and ambiguous package mappings are rejected. Inferred context does not prove distribution ownership, execution or vulnerable-function use. Correlation adds no vulnerability counts.

## Reproduction and receipts

From the repository root, using the development environment:

```powershell
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe -m scripts.evaluate_evidence_integration replay
.venv/Scripts/python.exe -m scripts.evaluate_evidence_integration correlation
.venv/Scripts/python.exe -m scripts.evaluate_evidence_integration osv
```

The last command queries the live external OSV database; current responses can change. No credentials are needed. [Development source replay](development.json), [correlation controls](correlation-controls.json), [OSV repository results](osv-local.json), [raw OSV responses](osv-responses.json), [synthetic summary](synthetic-summary.json), [OWASP development](owasp-development.json), [validation](validation.json), [test](test.json), [PySASTBench](pysastbench.json), [operational smoke](offline-selfscan.json).

Linux runners `scripts/run_mcp_oracle.py`, `scripts/run_pymdown_oracle.py` and `scripts/run_sqlparse_oracle.py` require the hash-pinned source caches and dependency wheel directories recorded here. Source files are Git-blob/SHA-256 checked before execution. MCP source-context receipts cover 156 files, SQLparse 98 and pymdown 107. SQLparse's two non-UTF-8 fixtures were reversibly decoded from connector transcoding and verified against original Git blob hashes. Missing caches fail instead of substituting current code.

Targets execute only in the existing bounded, offline namespace runner: read-only source/dependencies, cleared environment, no host home/Windows mounts, no runtime network, per-process resource limits and ephemeral test files. Wheel extraction is data-only; no target setup/install hooks execute on the host. This is research isolation using a shared WSL kernel, not a hardened multi-tenant execution service.

- [MCP paired results](mcp-oracle.json), [source receipts](mcp-oracle-context.json), [wheel lock](mcp-oracle-wheels.json). Direct source imports use disclosed synthetic distribution version metadata, isolated pytest configuration and an explicit AnyIO plugin. The [first attempt](mcp-oracle-attempt1.json) failed collection because package metadata was absent; it is not scored as a security result.
- [Pymdown paired results](pymdown-oracle.json), [source receipts](pymdown-context.json), [wheel lock](pymdown-oracle-wheels.json). Fixed upstream tests/fixtures run against both revisions. The [first attempt](pymdown-oracle-attempt1.json) used a new configuration option absent in vulnerable code; its functional failure is preserved, and the final legitimate-input test uses an option supported by both revisions.
- [SQLparse results](sqlparse-oracle.json), [source receipts](sqlparse-context.json). Uses the MCP wheel lock for pytest. Its upstream patch regression passes on both revisions: do not count it as a verified security pair.
- The [first operational attempt](offline-selfscan-attempt1.json) failed immediately under the system Python because the declared `cvss` dependency was missing. The completed run uses the repository development environment; previous historical timeout reports remain untouched.

## Open gates

The earlier html-sanitizer pair remains reproduced. Of the original nine unverified pilot environments, MCP and pymdown now have selected paired security/functional checks; SQLparse has functional execution but no discriminating security oracle. Six environments have not been executed here: smolagents, urllib3, Requests, owlmixin, OctoPrint and sigstore-python. CVAT additionally needs isolated service/database fixtures; the Docker engine is unavailable. None of these is marked complete.

Individual-alert adjudication beyond proxy labels is unfinished. New mechanism candidates are source-supported; MCP and html-sanitizer also have reproduced upstream security behavior. Requests and smolagents need their own paired execution. Existing OctoPrint hash/redirect candidates are not confirmed vulnerabilities merely because they appear in application code or survive the repair.

Independent human labels were declined and remain absent. The exposed ten-project pilot cannot become an untouched evaluation after tuning. A fresh project-separated reserve, externally corroborated action locations, completed security oracles, measured real-code correlation benefit, related-work comparison and broader operational testing remain required for the proposed broad paper claim. No manuscript or publication promise is produced.
