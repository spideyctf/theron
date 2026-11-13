# Library-boundary detection improvements — 14 November 2026

**Two concrete flow gaps are repaired, with explicit limits.** Theron now tracks invoked module attributes selected by external data and known remote HTTP/HTML content reaching dangerous operations. Library inputs can be declared through validated trust-boundary models; these produce conditional advisory evidence rather than pretending a caller was observed.

Final analysis/API freeze: `634573431544a3ef16da99df5fcad35360372971`. The earlier successful CLI smoke at `a5fa583` is preserved separately; final operational outcomes are recorded in the receipt. [Protocol](PROTOCOL.md), [freeze history](freeze-history.json), [summary](summary.json), [reproduction script](../../../scripts/evaluate_library_flows.py).

## Implemented behavior

- Resolved `sys.modules`, `importlib.import_module` and builtin `getattr` preserve externally controlled module/member selections through assignment, loops and helper calls. A finding requires invocation of the selected target; a lookup alone, clean overwrite, string conversion or fixed dispatch table does not trigger this rule. The rule records target selection, not proven arbitrary-code execution.
- A narrow dominating `issubclass(..., BaseException/Exception)` constraint recognizes the tested exception reconstruction boundary. Unknown, shadowed, nonterminating or unrelated guards do not suppress the rule. This is not a claim that arbitrary exception subclasses or custom constructors are harmless.
- Requests and HTTPX response `.text`, `.content` and `.json()` are external-content sources, including supported session/client/async-client calls. Status metadata is not response content. BeautifulSoup parsing/selection propagates observed taint; clean literal HTML stays quiet for these flows. Streaming responses, arbitrary wrappers and all DOM operations are not modelled.
- Explicit models name a relative file, qualified function, parameter and nonempty reason. An optional `bs4.element.Tag` binding supports declared remote-form inputs. Unknown files/functions/parameters produce coverage notices. Models are accepted through CLI configuration and the local scan API; they are not inferred from parameter names or read automatically from a remote repository.
- Findings derived from model assumptions are `configured-flow`, advisory and medium-confidence. The reason, source/sink trace and caller-reachability uncertainty survive JSON/HTML/SARIF, API downloads and frontend details. Configured findings are excluded from observed MCP associations; directly observed reflected-call flows can be associated under the existing limited declaration model. The web form does not yet author models; API/CLI callers can supply them.

## Exposed real-code development results

All 22 original snapshots and 38 function hashes were verified against unchanged original metadata. All nine previously exposed cases remain represented; no CVE/filename exceptions were added to detector rules and no source, labels, spans or CWE matching were changed. [Default](default.json), [configured](configured.json), [class-boundary ablation](configured-no-sanitizers.json).

| Mode | Original vulnerable CWE/span cases with evidence | Original patched cases with evidence | Whole-file findings |
| --- | ---: | ---: | ---: |
| Default, no declared library boundaries | 0/9 | 0/9 | 0 |
| Two explicit library boundaries | 1/9 | 0/9 | 3 conditional advisories |
| Same boundaries, sanitizer constraints disabled | 1/9 | 1/9 | 5 conditional advisories |

The configured Celery case has two reconstruction-call findings at vulnerable lines 362/364, with source at the declared input boundary on line 339. Its patched calls at 403/405 stay quiet with class constraints enabled. Disabling those constraints restores two patched-call candidates while retaining the vulnerable findings; this demonstrates the bounded guard model, not exploitability.

MechanicalSoup has a conditional file-read finding at vulnerable line 234, source at its declared remote-form boundary on line 188. Its patched form-handling path stays quiet. This mechanism is CWE-22 evidence while the original upstream case uses coarse CWE-20, so **it does not increase the original CWE-matched count**. Separate semantic developer observations cover two unsafe mechanisms with their two patched counterparts quiet. They are not independent labels, real-world precision/recall or a 2/9 held-out accuracy result.

The original final `4c166e0` result of 0/9 remains unchanged. The current **unconfigured** probe also remains 0/9. The other authorization, object-permission, key-confusion, credential-permission, dialect-specific SQL-fragment and protocol-state gaps remain unresolved. Explicit models address missing library trust context; they do not implement those security semantics. No independent human adjudication or fresh holdout has occurred.

## Synthetic regression results

All **1,470 variant classifications and per-case alert counts remain unchanged**, across the three exposed OWASP splits and PySASTBench. Labels and adapters are unchanged. This is regression evidence, not new unseen-code accuracy.

| Corpus | TP / FN / FP / TN | Recall | Precision |
| --- | --- | ---: | ---: |
| OWASP development | 202 / 77 / 9 / 449 | 72.40% | 95.73% |
| OWASP validation | 77 / 7 / 0 / 164 | 91.67% | 100% |
| OWASP exposed test | 65 / 24 / 0 / 156 | 73.03% | 100% |
| PySASTBench | 93 / 26 / 4 / 116 | 78.15% | 95.88% |

[Development](development.json), [validation](validation.json), [test](test.json), [PySASTBench](pysastbench.json). The unresolved PySASTBench label remains an error. Fixed-file review burden remains 17 alerts across 14 files, 13 outside label matches. No confidence/recall threshold was weakened to increase a score.

## Validation and operational limits

**605 Python tests, 14 frontend tests, TypeScript and production build pass.** One existing dependency deprecation warning remains. Original controls cover unsafe/safe reflection, class guards and overwrites, HTTP metadata/body distinctions, clean/remote HTML, imported helpers, model validation, missing declarations, CLI/API export delivery, frontend evidence classification and MCP exclusion. No app/browser/server, scanned module, exploit, archive or MCP command was executed.

The first working-tree three-module scan exceeded 120 seconds; [that failure is retained](initial-workingtree-timeout.json). Repeated source traversal of attribute prefixes and rebuilding fixed API-return tables were removed. A counter-based complexity regression guards against exponential prefix revisits without a flaky timing threshold. The first sanitizer ablation also incorrectly disabled reflection facts; [its adverse result](initial-freeze-no-sanitizers.json) and subsequent correction remain in the history.

A later offline SAST/AI/agentic CLI smoke on pinned self-target `4c166e0` completed in **110.77 seconds** under the 120-second bound. It staged 275 text inputs and analyzed 273; two oversized historical metadata files were skipped with context coverage notices. The three application findings are informational: two unresolved tuple mappings and an analysis-budget notice. There are 12 context findings, including the two size-limit notices; these are not independently adjudicated vulnerabilities. [Operational receipt](offline-selfscan.json), [input byte inventory](offline-self-inputs.json), [smoke script](../../../scripts/check_library_operations.py).

The offline smoke excludes SCA and network transport and is a single run. It is not comparable to the earlier working-tree timeout as a speedup ratio because the input inventories differ. It also does not replace the preceding live four-module operational evidence or establish production capacity. Analysis-budget and unsupported-shape coverage remain visible; zero application vulnerability alerts is not a clean-repository certification.

The [original delivery fixture JSON](original-delivery-fixture.json), [HTML](original-delivery-fixture.html) and [SARIF](original-delivery-fixture.sarif) contain one observed reflected-call flow and one configured advisory. They are original inert examples using a placeholder repository, not real project findings.

## Configure a library boundary

Use only a model justified by the actual application contract. For example, when this function really receives external operation records:

```yaml
analysis_entrypoints:
  - file: service/decoder.py
    function: Decoder.convert
    parameter: record
    reason: The service passes externally supplied operation records here
```

`type: bs4.element.Tag` is available for an explicitly declared HTML form/tag input. Paths use `/`, stay relative and must match the collected file. Function names are qualified within that file, such as `Browser.get_request_kwargs`. Receivers `self`/`cls`, path traversal, duplicate entries and unsupported types are rejected. A typed model is an assumption, not proof that the caller supplied that type. See the [disclosed development models](entrypoint-models.json); do not silently apply them to unrelated projects.

The local API accepts the same array as optional `analysis_entrypoints` in `POST /api/scans` (up to 100 entries). The standard UI starts unconfigured scans and displays configured evidence if the API caller supplied models. Configured findings remain advisory even when their severity denotes a dangerous operation.

## Reproduce

From a checkout with scanner/rules matching `6345734`, installed development/web dependencies and the existing pinned caches:

```powershell
.venv\Scripts\python.exe -m scripts.evaluate_library_flows
.venv\Scripts\python.exe -m pytest tests -q
cd frontend
npm ci
npm test
npm run build
```

If the 22 original source files are absent, use the published original final-evaluation input receipts to fetch only those pinned files from its frozen study checkpoint `1043ed4`, then reuse that cache. The evaluator verifies the original metadata ledger and every original file/function hash. It does not download a new holdout.

`python -m scripts.check_library_operations` stages the fixed input snapshot from Git and reruns the offline CLI with a 120-second limit. The script checks scanner/rule bytes against the final freeze. Runtime observations vary; the input byte inventory is pinned. [Artifact hashes](artifact-hashes.json) use UTF-8 with LF-normalized newlines.

Model references: [Python getattr/issubclass](https://docs.python.org/3/library/functions.html), [Requests response content](https://requests.readthedocs.io/en/latest/user/quickstart/#response-content), [BeautifulSoup selection](https://www.crummy.com/software/BeautifulSoup/bs4/doc/#css-selectors), [Kombu encoding utilities](https://docs.celeryq.dev/projects/kombu/en/stable/_modules/kombu/utils/encoding.html).
