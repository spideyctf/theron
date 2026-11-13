# ASGI/archive flow and delivery completion — 13 November 2026

Implementation freeze: `d8fc59850ff1c261c29cdf53b53ec90c3571f5fb`. [Protocol](PROTOCOL.md), [freeze history](freeze-history.json), [reproduction script](../../../scripts/evaluate_flow_completion.py).

## Completed scope

Typed Starlette ASGI fields now propagate through supported synchronous AnyIO/asyncio thread callbacks, fixed-arity tuple returns, local imports and helpers into file-response sinks. Slot-specific propagation avoids treating unrelated metadata as user input. Normalized `commonpath` guards remain boundaries; character-prefix checks do not. Unknown tainted tuple shapes produce review notices. Async callbacks passed to synchronous thread wrappers are not treated as executed.

Resolved tar extraction distinguishes explicit data filters, fully-trusted filters and unknown runtime/custom filters. Observed external/model-output archive file objects plus explicit fully-trusted extraction support a static flow finding. A tainted archive filename alone does not prove byte control. Missing/custom/default filters produce informational review notices, because the target runtime is unknown. Instance filters do not leak between archive objects. These checks do not prove all archive safety properties.

## Frozen results

| Material | Outcome | Interpretation |
| --- | --- | --- |
| psiTurk audited template flows | 2 unsafe matched; 0/2 patched matched | Existing exposed developer units |
| Starlette audited file-response flow | 1 unsafe matched; 0/1 patched matched | New exposed developer unit, source 111 → sink 192 |
| Luigi extraction calls | Informational runtime/context review | No fabricated confirmed vulnerability |
| Original real-code label errors | 2 retained | Hash mismatches remain errors |
| OWASP development | TP202 / FN77 / FP9 / TN449 | Recall 72.40%, precision 95.73% |
| OWASP validation | TP77 / FN7 / FP0 / TN164 | Recall 91.67%, precision 100% |
| OWASP test | TP65 / FN24 / FP0 / TN156 | Recall 73.03%, precision 100% |
| PySASTBench | TP93 / FN26 / FP4 / TN116; 1 label error | Recall 78.15%, precision 95.88% |

All synthetic outcomes are unchanged. All 1,230 OWASP cases remain scored; these splits are exposed tuning/regression data. PySASTBench retains 17 alerts across 14 fixed files, 13 outside label matches, including nine advisory weak-hash selections. Label precision does not measure whole-report alert correctness.

[Real developer probes and ablations](real-development.json), [six provisional units](developer-units.json), [bounded package-context probe](package-context.json), [development](development.json), [validation](validation.json), [test](test.json), [PySASTBench](pysastbench.json).

All nine validation CVEs are exposed development material; 28 original files were checked against pinned receipts. The two original function-hash errors are preserved. The four additional Starlette package files were already exposed in the preceding audit; their receipts remain there. The flow model now detects Starlette even without those extra files; acquiring context alone did not fix detection. Semantic source/sink units are separate from original patch spans and coarse CWE metadata. Three matched flows across two CVEs are not an independently labelled real-world accuracy denominator. Final real test source remains closed.

## Delivery acceptance

| Layer | Verification |
| --- | --- |
| Directory collection and analysis | CLI scans an original inert source fixture; no fixture module executed |
| Normalization and correlation | Two high-severity flows, one INFO notice, one association group referencing the same two fingerprints; no extra vulnerability count |
| JSON / HTML / SARIF CLI exports | Source/sink locations, IDs and review classification retained |
| API results and JSON/SARIF downloads | In-process tests with backend-generated report and mocked repository transport |
| Frontend finding details and MCP links | Shared backend fixture renders traces, advisory notice and association links |
| Standalone HTML display | Trusted Theron renderer shows evidence kind, scope, maturity, source/sink trace and fingerprint |
| Regression suite | 552 Python tests; 13 frontend tests; TypeScript/production build pass |

Python emits one existing dependency deprecation warning. Tests do not launch the application, execute scanned code, extract an archive, run an MCP command or prove a live deployment. The HTML rendering test executes only Theron's trusted report-rendering script in an isolated test document. API transport is mocked and is not a live GitHub scan.

[Original JSON fixture](original-delivery-fixture.json), [HTML fixture](original-delivery-fixture.html), [SARIF fixture](original-delivery-fixture.sarif), [delivery metadata](delivery-check.json). Fixtures use a placeholder repository and original source; they must not be cited as real project findings.

## Reproduce

With the existing pinned benchmark/source caches and development dependencies installed, run from repository root:

```powershell
.venv\Scripts\python.exe -m scripts.evaluate_flow_completion
.venv\Scripts\python.exe -m pytest tests -q
cd frontend
npm ci
npm test
npm run build
```

`--skip-synthetic` reruns only developer/context/delivery probes. The evaluator checks detector freeze, original manifest membership and file hashes. Historical source-fetch scripts retain their older freezes; this evaluator consumes the pinned caches and receipts instead of downloading final-test source. [Artifact hashes](artifact-hashes.json) identify UTF-8 text normalized to LF line endings so Git checkout conventions do not change verification; the hash manifest excludes itself.

## Remaining work

This completes the bounded analyzer → exports/API → frontend increment. It does not complete the broad platform or establish publication readiness. Independent real-code labels, an untouched final evaluation, AI-specific accuracy, validated MCP associations, baseline comparison on comparable independently adjudicated units, reviewer benefit and operational/load evaluation remain outstanding. Stored XSS, runtime-dependent behavior, arbitrary callbacks/tuple shapes, regex DoS and several protocol/authorization flaws remain outside demonstrated coverage. A patched flow staying quiet proves only the tested boundary, not that its repository is secure.

Model references: [ASGI HTTP scope](https://asgi.readthedocs.io/en/latest/specs/www.html#http-connection-scope), [AnyIO synchronous worker calls](https://anyio.readthedocs.io/en/stable/api.html#anyio.to_thread.run_sync), [Python tar extraction filters and version changes](https://docs.python.org/3/library/tarfile.html#extraction-filters).
