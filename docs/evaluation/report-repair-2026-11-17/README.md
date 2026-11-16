# Source-grounded report repair

17 November 2026. Detector checkpoint `b7ca4da`, followed by evaluation provenance/documentation updates. **933 Python tests, 25 frontend tests, production frontend build, dependency consistency and redirect-origin checks pass.** One existing FastAPI/Starlette dependency deprecation warning remains.

## Same-source before and after

The supplied report was replayed against the same **65 collector-eligible files** at `chris-koch-penn/gpt3_security_vulnerability_scanner@eafa783645f4132b2d84a23c3dfb84d74985591d`. Every source length and Git blob hash was checked; SHA-256 receipts are archived. All four modules ran with experimental checks enabled, matching the original scan's settings. No target program/package was imported or executed.

| Measurement | Supplied report | Repaired replay |
| --- | ---: | ---: |
| Application-section entries, including information | 40 | 21 |
| Non-informational candidates | 38 | **11** |
| Critical labels | 25 | **0** |
| Source/sink flows among remaining candidates | Mixed with unsupported labels | **9** |
| Unverified credential literals among remaining candidates | 2 | **2** |
| Information/review/configuration observations | 2 | **10** |
| README agent/LLM contextual matches | 20 | **0** |

This is development correction on exposed source, not an independent accuracy estimate. The 11 candidates are not 11 confirmed vulnerabilities. Two path alerts concern identical copied Python fixtures; the SQL/command snippets still require deployment/runtime interpretation. Cached replay timing excludes GitHub downloading and is not a performance comparison to the original live scan.

The **23 reviewed false-positive paths** are no longer emitted: 20 Python SQL matches, two filtered template paths and the encoded `innerHTML` assignment. Ordinary SQL constructions have SQL/source traces instead of invented model-output attribution. Three previously missed paths now have the proper source/sink reports: multiline shell execution at `Command Injection/exec.js:18`, object-form SQL at `SQL Injection/mysql.js:35`, and `jinja2.Template` construction at `Server Side Template Injection/test.py:11`.

## What changed

- **Python SQL fallback:** grouped the input alternatives so an import, request lookup or decorator cannot match without the SQL execution pattern.
- **AI attribution:** retired the old name-only AI taint regexes. Names such as `result` or `response` and callback parameters cannot prove a model-output source. Existing Python semantics and supported JS SDK bindings provide source evidence instead.
- **JavaScript/TypeScript:** a bounded Tree-sitter syntax pass now handles selected Express routes, Node HTTP data callbacks, imported process/SQL APIs, variable aliases, multiline calls, SQL option objects, explicit interpreter flags and shell options. Fixed executable argument arrays and parameterized SQL do not become injection merely because their value parameters are untrusted. Parse failures and analysis limits remain notices.
- **HTML encoding:** suppression requires the complete supported pure text-node encoder expression, an unchanged binding and an HTML text context. A helper name alone is insufficient. Raw inputs, replacement/reassignment, attribute/script contexts, mixed raw/encoded values and unknown escaped literals do not receive that proof.
- **Python templates:** track default-delimiter exclusion through ordered replacements and construction snapshots. Nullable-input branches preserve proofs only on the relevant tainted paths. Trusted template syntax surrounding a dynamic expression, partial filtering, delimiter reintroduction, decoding and custom delimiters cannot inherit a text-only proof. `jinja2.Template` construction is checked directly.
- **Session interpretation:** values stored as ordinary remembered data are information. User-controlled session keys remain boundary candidates. Conventional identity/privilege/token keys use an explicit advisory key-name contract (including `userid`, `user_id`, `role`, authentication flags and token keys), not a claim of verified authentication impact. Fixed-key information is not a safety verdict when the application later trusts that value.
- **Deployment facts:** interface binding, debug mode and peer-address shell use remain visible without automatically asserting an exploitable vulnerability. Information evidence distinguishes configuration/review context from incomplete coverage.
- **Documentation domain:** ordinary README vulnerability prose no longer establishes agent permissions or prompt-injection instructions. Explicit agent/instruction files remain checked.

JavaScript still has bounded, selected contracts—not general whole-program reachability, arbitrary framework/interprocedural/heap semantics or Python-equivalent language coverage. Some unrelated JS heuristics remain advisory. Unresolved sources, customized libraries, callbacks and dynamic dispatch require further review. The original Python-2 file remains unparsed, a JS snippet now has an explicit parse notice, and absent manifests still prevent dependency matching.

The parser is data-only; Node is not used to execute scanned code. Runtime packages are Tree-sitter 0.25.x, JavaScript grammar 0.25.x and TypeScript grammar 0.23.x. Python **3.10+** is now required; 3.12 is the verified environment. API/grammar contracts follow the primary [Python bindings documentation](https://github.com/tree-sitter/py-tree-sitter) and [TypeScript grammar](https://github.com/tree-sitter/tree-sitter-typescript).

## Regression evidence

All **1,470 previously exposed synthetic outcomes**, including the same existing unscorable PySASTBench case, retain their label outcomes. Total per-file alert payloads are not identical: new template coverage creates additional unrelated-CWE candidates on some files.

| Partition | TP / FN / FP / TN | Recall | Label-matched precision |
| --- | --- | ---: | ---: |
| OWASP development | 202 / 77 / 9 / 449 | 72.40% | 95.73% |
| OWASP validation | 77 / 7 / 0 / 164 | 91.67% | 100% |
| OWASP test | 65 / 24 / 0 / 156 | 73.03% | 100% |
| PySASTBench | 93 / 26 / 4 / 116; one unscorable | 78.15% | 95.88% |

An initial iteration overclassified ordinary formatting as unsafe and demoted all session writes, introducing one development false positive and reducing validation recall. That attempt is retained in [initial regression](initial-regression/synthetic-summary.json). The implementation was refined with generic formatting and session-key counterexamples; the final outcomes above preserve the prior classifications. The parser/source tests also check genuine unsafe calls, safe parameterization, helper mutation, custom delimiters and altered framework contracts. Variable names are deliberately not treated as proof of an external source.

## Artifacts and reproduction

- [Original per-alert audit](../../reviews/gpt3-scanner-report-2026-11-17.md).
- [Comparison and code/parser provenance](comparison.json), [65 verified source receipts](source-receipts.json).
- [Repaired JSON](repaired-report.json), [HTML](repaired-report.html), [SARIF](repaired-report.sarif).
- [Synthetic summary](synthetic-summary.json), with full partition records alongside it.

Run `.venv/Scripts/python.exe -m scripts.evaluate_report_repair --report PATH_TO_ORIGINAL_JSON --synthetic` with the verified ignored blob cache populated. The driver asserts removal of the audited paths and detection of the three additional cases. It never installs or executes target source. Original reports and earlier frozen evaluations are unchanged.

The source is now development-exposed. A new registered reserve, independent labels and application/runtime validation remain necessary before broad research or production claims. Backend activation is operationally separate: the attempted automatic restart was blocked by automatic approval review with reason “blocked by policy”; a manual restart is needed unless the running backend has since been restarted by the user.
