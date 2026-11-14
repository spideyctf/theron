# Theron: realistic project assessment and improvement plan

**Assessment date:** 15 November 2026. **Current correlation checkpoint:** `7b99d5c`. **Detection benchmark checkpoint:** `7b64719`. **Paired behavior evidence:** `15a4356`.

Latest increment: [tool-level correlation and package-attribution evidence](evaluation/tool-correlation-2026-11-15/README.md). Supported tool registration, bounded local call paths, collected distribution-record claims, source/advisory digests and frontend provenance are implemented. All 16 original controls match expectations, and two pinned upstream source examples each produce one tool group under generated configurations. These checks do not establish independent edge accuracy, new vulnerabilities or improved review decisions; the real-code research gate remains open.

## Current verdict

Theron is a working, evaluated research prototype with a usable local developer workflow. It combines Python analysis, dependency advisories, AI/agent checks and inspectable reports. Engineering quality and behavioral verification have improved substantially.

It is suitable for a technical demonstration and a clearly scoped development/evaluation study. The evidence does **not yet support** a broad claim of industry-grade coverage, unseen-project superiority or a validated novel benefit from combining code, dependency and MCP evidence. Publication acceptance cannot be predicted from test counts or benchmark percentages.

The [README](../README.md) presents the strengths and practical entry points. This document records the current facts and the work that changes the readiness decision. Detailed historical artifacts remain intact.

## What actually works

| Area | Implemented today | Practical boundary |
| --- | --- | --- |
| Collection | Local repositories and commit-pinned GitHub source; exclusions and profiling | File/read/download limits and skipped inputs remain explicit |
| Python analysis | Selected framework/CLI sources, local imports/helpers, containers, returns, instance state and context-specific sanitizers | Bounded analysis; dynamic behavior and unfamiliar libraries are not comprehensively resolved |
| Application detection | Supported command/code injection, SQL/XPath/LDAP, deserialization, filesystem, redirect and outbound-request flows | Per-API/source models; whole-project vulnerability completeness is unestablished |
| Security obligations | Selected DRF object checks, JWT/JWS/HMAC, HTTP framing, HTML normalization, TLS pool/hostname state and AST callable boundaries | Advisory models with library/caller assumptions, not general policy, cryptography or protocol proofs |
| AI and agents | Selected model-output-to-dangerous-operation flows, provider-shaped credentials, MCP/instruction/tool/configuration checks | No comprehensive prompt-injection, RAG, agent permission or resource-isolation model |
| Dependencies | Exact-version OSV queries with pagination/failure handling, alias grouping, severity provenance, fixed boundaries and CycloneDX SBOM | Unsupported ranges/locks, installation, distribution ownership and vulnerable-function reachability remain unresolved |
| MCP context | Supported tool declarations, bounded helper/API call paths, original findings and distribution-metadata/dependency links, with source/advisory provenance | Static associations and metadata claims do not prove execution, installation or vulnerable-function reachability |
| Review and delivery | CLI, local API/React UI, filters, evidence, baselines, CI thresholds and JSON/HTML/SARIF/SBOM | In-memory history and single-user operation; no durable multi-user review service |
| Verification | Pinned source/dependencies, import-origin checks and selected paired behavior tests | Research harnesses, not full upstream-suite acceptance or a production verification service |

The frontend displays the principal finding, obligation, dependency and correlation fields, plus full report JSON. This does not mean every backend fact has a dedicated visual component. JS/TS checks do not have Python-equivalent semantic coverage. Structured infrastructure/CI analysis and broader platform features remain roadmap work.

## Current metrics and their meaning

### Engineering and operations

| Measurement | Recorded result | Meaning |
| --- | --- | --- |
| Python suite | **823 pass**, one dependency deprecation warning | Current correlation-increment regression checkpoint |
| Frontend | **19 pass; production build passes** | Current correlation symbols, provenance and unresolved-state UI tested |
| Synthetic stability | **1,470 case outcomes and alert counts unchanged** after the latest detector changes | Recent changes preserve those exposed regressions |
| Offline smoke | **52.89 seconds / 120 seconds**, 273 files read from 275 selected | One pinned offline SAST/AI/agentic workload; not a capacity or speed ranking |
| Incomplete coverage | Three application notices, 12 context findings, two oversized files in that smoke | A completed scan is not complete analysis of every input |
| Live repository OSV | **134 completed unique queries**, no advisory matches, one unresolved-range notice | Exact declarations were queried; unpinned dependencies prevent an installed-environment safety conclusion |
| OSV calibration | **6/6 advisory-specific checks pass** | Three vulnerable/repaired version pairs match expectations for named CVEs; repaired references can match other advisories |
| Correlation controls | **13/13**, four inferred context edges, unchanged vulnerability payloads | Original engineering controls; zero additional discoveries or measured reviewer benefit |
| Tool-level correlation controls | **16/16 expected outcomes**, full finding payloads unchanged on/off | Original controls and four input ablations; not independent real-code accuracy |

Earlier operational crashes and two 120-second timeouts are preserved. Later successful runs do not erase those failures. The current smoke excludes SCA/network work and is not comparable to full four-module live scan duration.

Sources: [latest follow-up](evaluation/evidence-2026-11-14/FOLLOWUP.md), [current smoke](evaluation/evidence-2026-11-14/hostname-followup/offline-selfscan.json), [OSV repository scan](evaluation/evidence-2026-11-14/osv-local.json), [OSV calibration](evaluation/evidence-2026-11-14/osv-calibration.json), [correlation controls](evaluation/evidence-2026-11-14/correlation-controls.json).

### Synthetic detection

These corpora and selected outcomes informed development. Their validation/test names are historical split labels; they are **not currently untouched holdouts**.

| Corpus/split | TP | FN | FP | TN | Recall | Label-matched precision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| OWASP development | 202 | 77 | 9 | 449 | 72.40% | 95.73% |
| OWASP validation | 77 | 7 | 0 | 164 | 91.67% | 100% |
| OWASP test | 65 | 24 | 0 | 156 | 73.03% | 100% |
| PySASTBench | 93 | 26 | 4 | 116 | 78.15% | 95.88% |

OWASP contributes 1,230 cases across 14 categories. PySASTBench contributes 240 recorded cases, with one unresolved label/error excluded from its confusion matrix. Its fixed files still produce **17 alerts across 14 files**, with 13 alerts outside label matches. Zero label-matched false-positive cases on OWASP test does not establish zero false-positive alerts across real applications.

The pinned OWASP test baselines record Bandit 1.9.4 at **70.79% recall / 57.27% precision** and Semgrep CE 1.185.0 at **34.83% / 58.49%**. Theron's result is stronger on this adapter/corpus, but it was tuned on exposed outcomes. Baseline support, rules and evaluation dates differ. No unseen-project or general tool-superiority conclusion follows, and no cross-tool speed ranking was measured.

Sources: [current per-split reports](evaluation/evidence-2026-11-14/hostname-followup/synthetic/synthetic-summary.json), [baseline methodology and staging correction](evaluation/step5-2026-11-13/README.md).

### Real-code detection and behavior verification

| Measurement | Current fact | Interpretation |
| --- | --- | --- |
| Earlier final source probe | **0/9** vulnerable reference matches | Adverse frozen CWE/function-span proxy; not independently adjudicated whole-project recall |
| Original ten-project pilot | **0 strict matches / 8 CNA-labelled cases**, two missing labels | Preserved before source-guided tuning |
| Current ten exposed mechanisms | **4/10** have relevant default candidates; none in repaired mechanism units | Development evidence, not fresh 40% real-world recall |
| Current strict CNA match | **2/8 labelled cases**, two missing labels | Separate from the semantic count; CWE agreement alone does not validate an alert |
| Earlier six exposed mechanisms | **5/6** relevant candidates, none in repaired mechanism units | Another source-guided set; CVAT remains missed |
| Runtime behavior study | **10 selected pairs distinguish revisions** | Selected behavior verification, not ten scanner detections |

The original pilot contains one Requests project-alias overlap with earlier work. The registration/results retain it; the project-separated subset is nine cases, seven CNA-labelled. All pilot source is now exposed. A new evaluation must exclude canonical aliases and prior exposure, not rename these cases as a holdout.

The behavior study comprises **five unmodified upstream pairs, two adapted upstream pairs and three author-derived pairs**. These are not complete upstream suites or full Vul4Py acceptance:

| Project | Paired behavior observed | Default mechanism status |
| --- | --- | --- |
| html-sanitizer | Compatibility normalization reintroduces markup before repair | Candidate present |
| MCP SDK | Malformed-message validation fails before repair; repaired handlers continue | Candidate present |
| smolagents | Indirect callable/module access accepted before repair and rejected after | Candidate present |
| Requests | Verification policy/pool reuse differs in an adapted local TLS transport | Candidate present |
| pymdown | Path restriction fails before repair and passes after | Miss |
| owlmixin | Historical YAML loading reaches a command-recording stub before repair; repair rejects it | Miss; version/caller assumptions matter |
| sigstore-python | Missing signed-time evidence accepted before repair and rejected after | Miss |
| urllib3 | Wrong-hostname trusted certificate accepted before repair and rejected after | Version-dependent coverage notice, not a vulnerability candidate |
| SQLparse | 41-character lexer input exceeds a local 2-second deadline before repair; repair completes in about 0.0043 seconds | Miss |
| OctoPrint | Original helper accepts a forged forwarded identity before repair; repair retains the transport peer | Miss; full proxy/authentication behavior unverified |

Requests and owlmixin use adapted upstream environments; urllib3, SQLparse and OctoPrint use authored adapters. SQLparse's original patch test passes on both revisions. OctoPrint's original new-API tests cannot run against the absent old API. Additional adapters establish narrower observations, not full application impact.

Source hashes, function locations, dependency locks, import-origin checks and failed attempts are retained. A pytest import-order problem was corrected and affected checks rerun. Failed imports and API mismatches are not scored as verified vulnerabilities. CVAT's service/database environment remains unrun: Docker startup fails on a stale runtime socket, and automatic approval review rejected recovery. That blocker is separate from detection quality.

Sources: [checked upstream summary](evaluation/evidence-2026-11-14/upstream-summary.json), [adaptations and receipts](evaluation/evidence-2026-11-14/FOLLOWUP.md), [current source replay](evaluation/evidence-2026-11-14/hostname-followup/development.json), [earlier final probe](evaluation/final-validation-2026-11-13/README.md).

### Individual alert interpretation

The action-level review of **14 original pilot alerts** records exact source, function and action hashes:

- **Four** mechanisms have source support and selected runtime corroboration.
- **Eight** weak-hash occurrences have visible ETag/cache or UI fingerprint uses. They are not eight confirmed vulnerabilities or detections of the reference CVE.
- **Two** redirects follow a project-specific validator and fallback assignment. The helper is unmodelled; its semantics/configuration remain unresolved.

This is an assistant source assessment supported by external tests. Independent human adjudication has not occurred; these counts are not an independently labelled precision estimate. Zero repaired-unit candidates in four mechanisms does not establish zero false positives across the platform.

Source: [individual alert review](evaluation/evidence-2026-11-14/individual-alert-review.json).

## What is still lacking

1. **Generalization.** Exposed synthetic scores are stronger than the real-code proxy results. Libraries introduce state, callbacks, custom policies, guard ordering and implicit boundaries beyond current models.
2. **Detection of reproduced issues.** Five pilot mechanisms remain misses and urllib3 remains a version-dependent notice. Reproducing issues improves reference evidence but does not repair detection.
3. **Alert interpretation.** Custom guards, security use of hashes and library-version behavior need stronger models. Unknown states must remain explicit rather than become fabricated vulnerability or safety claims.
4. **Independent evaluation.** Real-code locations began as CWE/patch/function proxies. Action-level review improves them but does not create an untouched, independently labelled dataset.
5. **Cross-layer contribution.** Code/dependency/MCP joins work on original controls, but additional correct discoveries, better prioritization or improved review decisions remain unmeasured on real code.
6. **Verification breadth.** Selected/adapted pairs do not cover complete upstream suites, proxy deployments, service recovery or CVAT's database/permission fixtures.
7. **Platform and operations.** Stronger JS/TS semantics, structured infrastructure/CI analysis, more lock/range formats, broader AI resource/policy models, durable storage and larger-workload reliability remain unfinished.

## Prioritized improvement plan

| Priority | Work | Concrete acceptance evidence |
| --- | --- | --- |
| P0 | Repair reproduced gaps: path containment, legacy loader defaults, signed-time/certificate state, lexer resource patterns and proxy/custom authorization | Frozen rules with unsafe, repaired, legitimate and ambiguous controls; exact action/assumption evidence; existing corpora rerun with all new alerts/misses reported |
| P0 | Improve guard and version interpretation | Ordering, object identity, aliases and reassignment respected; unresolved guards stay review notices; declared versions are not assumed installed |
| P0 | Strengthen per-alert reference labels | Original source/action hashes, affected behavior and independent upstream oracle/specification per case; uncertain and disputed cases retained |
| P0 | Freeze a fresh project-separated reserve after tuning | Registration before source inspection; canonical-alias exclusions; immutable source/labels/scoring; no reserve-driven detector changes; adverse outcomes published |
| P1 | Finish service/integration validation | Working CVAT environment and selected permission/functional tests; original proxy/integration checks where claimed; setup failures separated from behavior failures |
| P1 | Measure code + OSV + MCP benefit | Predeclared real-repository tasks; code-only, dependency-only and combined modes; independently supported links/decisions; correct additions, false associations and unknowns reported |
| P1 | Validate operational reliability | Repeatable workload sizes, wall time/memory/coverage, API failures, queue/recovery tests and Windows/Linux checks |
| P2 | Expand platform coverage | Supported-contract documentation, positive/negative controls and external evaluation per language/framework/format before broad coverage claims |
| P2 | Improve review-service durability | Persistent results/review state, job recovery and measured workload behavior; multi-user features if the product scope requires them |

Fix recurring mechanisms rather than tuning by CVE identifiers, source filenames or expected benchmark outcomes. Retain historical reports, disagreements, missing labels and coverage limits.

## Research goal and readiness gates

The product goal can remain broad: unified evidence-driven security analysis for AI-enabled and agentic applications. The research claim needs a demonstrable benefit within that platform. Three evaluation dimensions provide a practical target:

1. **Detection correctness and generalization:** better supported decisions on new real code, with all misses and false alerts included.
2. **Evidence validity:** reproducible action locations, source/version provenance and external checks distinguishing unsafe and repaired code.
3. **Incremental cross-layer value:** measured improvement in correct discoveries, prioritization or review decisions from code, dependency and MCP evidence together.

| Gate | Current status |
| --- | --- |
| Working scanner and local UI | Implemented within documented scope |
| Regression and exposed benchmark reproduction | Strong engineering evidence |
| Selected real-library behavior verification | Substantial progress; adaptations and scope limits remain |
| Independent action-level labels and fresh generalization | Incomplete |
| Validated incremental correlation benefit | Unmeasured on real code |
| Broad platform/production reliability | Incomplete |
| Supported novelty and related-work comparison | Not yet established for the proposed broad contribution |

The next research milestone is a frozen evaluation supporting a specific detection/evidence/correlation benefit on independently labelled real code. Current results support the prototype and its development progress; they do not yet establish that broader contribution. No percentage-complete estimate or publication promise is justified.

## Evidence and reproduction

- [Latest paired checks, caveats and reproduction](evaluation/evidence-2026-11-14/FOLLOWUP.md)
- [Current synthetic results](evaluation/evidence-2026-11-14/hostname-followup/synthetic/synthetic-summary.json)
- [Baseline methodology and corrections](evaluation/step5-2026-11-13/README.md)
- [Quality and report interpretation](QUALITY.md)
- [Platform contract and roadmap](PLATFORM.md)
- [Research direction and historical checkpoints](RESEARCH.md)

This assessment describes recorded evidence. The documentation change itself does not rerun benchmarks, call OSV or turn earlier validation into a new experiment.
