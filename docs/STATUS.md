# Theron: current progress and research-readiness decision

**Current detector `7b64719`:** [full follow-up](evaluation/evidence-2026-11-14/FOLLOWUP.md). 763 Python tests pass; frontend unchanged from 17 tests/build passing. API shadowing and replaced-manager precision issues are fixed. TLS hostname state distinguishes checks before/after a handshake and keeps unknown library-version defaults as coverage notices. All ten pilot projects now have selected behavior pairs that distinguish revisions: five upstream, two adapted upstream and three author-derived. SQLparse/OctoPrint adapters do not replace full upstream or application validation. Four of ten exposed mechanisms remain default vulnerability candidates; none appear in repaired units. Four original alerts have runtime corroboration, eight hash uses are not confirmed vulnerabilities, and two custom redirect guards remain unresolved. OSV calibration passes 6/6 advisory-specific checks. All 1,470 synthetic outcomes are unchanged; current bounded smoke is 52.89 seconds. CVAT service verification, reproduced detection misses, custom authorization, independent labels/fresh evaluation and measured real-code correlation benefit remain open. Prior paragraphs and tables below describe historical checkpoints.

**Latest local checkpoint `f370de1`, 14 November 2026:** [full results and remaining gates](evaluation/evidence-2026-11-14/README.md). 746 Python tests, 17 frontend tests and build pass. Four new security-state models produce candidates on 4/10 exposed pilot mechanisms (strict CNA 2/8 labelled), none on repaired units; this is source-guided development. MCP and pymdown have selected reproduced upstream security/functional pairs, alongside the earlier html-sanitizer pair. SQLparse has 427 functional passes/3 expected failures per revision, but no discriminating security oracle. Six other pilot environments remain unexecuted; CVAT services are unavailable. OSV completes 134 unique live version queries with no advisory matches and one unresolved-range notice. Thirteen original correlation controls pass, with four inferred context edges and no new vulnerabilities or measured real-code review benefit. The bounded smoke completes in 53.94 seconds; all 1,470 synthetic outcomes remain unchanged. Broad research readiness remains unmet. Tables below preserve the preceding checkpoint and must be read as historical.

Updated 14 November 2026 (Asia/Calcutta). Current detector checkpoint: `ab48e94`; initial mechanism evaluation: `6eb6aee`. [Latest evidence and reproduction](evaluation/mechanisms-2026-11-14/README.md).

**Decision: working research prototype; broad publication-readiness gates remain unmet.** The product goal stays broad. A paper must make claims supported by the measured implementation, rather than imply that every security layer is complete. No percentage-complete estimate or acceptance promise is justified.

## What works now

| Capability | Implemented behavior | Boundary |
| --- | --- | --- |
| Repository collection | Local directories and pinned GitHub repositories; project/framework profiling; coverage notices | File limits, skipped/unresolved inputs and analysis budgets remain |
| Python flow analysis | Selected web/CLI/AI sources, local helpers/imports, containers/tuples, selected sink and sanitizer models | Bounded analysis; untyped library parameters and unfamiliar APIs are not assumed attacker-controlled |
| Required security conditions | Declared DRF object policies; JWT settings/key families; verified JWS payload identity; finite HMAC key-format rejection; selected HTTP numeric/coding/footer patterns | Advisory candidates with assumptions; custom IAM and general crypto/protocol correctness are not established |
| AI and agents | Selected model-text-to-dangerous-operation checks, unsafe loaders, MCP/instruction/configuration checks | No comprehensive RAG, prompt-injection, agent permission or runtime exposure model |
| Dependencies and SBOM | Exact-version OSV matching, alias grouping and severity provenance; CycloneDX inventory | Version ranges, installation, deployment and vulnerable-function reachability remain unresolved where unsupported |
| Secrets | Redacted provider-shaped credential candidates | No credential authentication or proof that a value is live |
| Cross-layer context | Experimental local MCP declaration-to-file-to-existing-flow relationships | No proven runtime reachability, independent edge accuracy or measured triage benefit |
| Developer workflow | CLI, local single-user API/frontend, evidence details, filters, fingerprints/baselines, CI thresholds and JSON/HTML/SARIF/SBOM exports | No persistent multi-user review service |
| Controlled verification | Explicit opt-in namespace isolation, read-only sources, cleared environment, no runtime network, locked wheels and bounded resources | Research scripts, shared WSL kernel, per-process limits; no hardened multi-tenant verifier |

Seven original required-condition findings are shared through backend-generated fixtures, API downloads, CLI exports, frontend details and standalone HTML. The frontend displays their required check, observations, assumptions and related locations; remediation copy is tested. This does not mean every possible backend fact has a dedicated visual panel.

## What has been measured

| Evidence | Current result | Interpretation |
| --- | --- | --- |
| Automated regression | **688 Python tests, 15 frontend tests, production frontend build pass** | Engineering confidence within tested behavior |
| Exposed OWASP test split | **73.03% recall, 100% label-matched precision**; TP 65, FN 24, FP 0, TN 156 | Already used during tuning; not fresh real-world accuracy |
| Exposed PySASTBench | **78.15% recall, 95.88% precision**; TP 93, FN 26, FP 4, TN 116; one unresolved label | Synthetic tuning evidence; 17 fixed-file alerts across 14 files, 13 outside label matches |
| Synthetic regression stability | All **1,470** outcomes and alert counts unchanged | No measured improvement on those exposed corpora |
| Six exposed mechanism cases | **5/6** vulnerable cases have relevant obligation candidates, **0/6** repaired mechanism units do; strict CNA-CWE matching **2/5**, one missing label | Source-guided development; original 1/6 result remains preserved. CVAT still missed |
| Ten-project Vul4Py pilot (one prior-project alias overlap) | **0 strict matches across 8 CNA-labelled cases**, two cases without CNA CWE labels; 46 application file snapshots, zero scanner/unit errors | Adverse changed-file/location proxy; not a defensible whole-project recall estimate |
| Same-byte pilot baselines | Bandit **54** alerts; Semgrep **100**; both cover all 46 files, with zero reported errors | Alert counts/repair-location overlaps do not establish semantic accuracy or superiority |
| New upstream runtime pair | html-sanitizer security test fails before repair and passes afterward; functional test passes on both | Reproduced a mechanism the scanner misses. Nine other pilot environments/oracles remain unverified |
| Earlier runtime evidence | One upstream Waitress test group and four author-derived adapter pairs distinguish old/new behavior | Keep upstream tests and adapters separate; CVAT remains unrun |
| Post-fix operational smoke | **84.04 seconds wall time / 120-second limit**, 273 files read, SAST/AI/agentic complete | One bounded offline run; budget/tuple/oversized-file notices remain. Two prior timeouts are preserved |

Original frozen results, including the earlier 0/9 final probe, are not rewritten. The new ten projects were selected deterministically from pinned external metadata before source inspection, excluding raw repository names in the earlier declared evaluation manifests. A final canonical-alias audit found one Requests project overlap; the fully project-separated subset is nine cases, seven CNA-labelled, with zero strict matches. The overlap is retained, and the future selection guard now checks aliases and preserves existing registrations. Their source is now exposed. Additional detector tuning against them needs a separate development interpretation and a new final reserve.

## What remains before the broad paper claim can hold

1. **Real-code generalization:** repair recurring causes rather than add case identifiers, then freeze and test a new project-separated reserve. The ten-project result currently gives no strict positive evidence of generalization.
2. **Independent behavior/labels:** complete paired upstream security and functional oracles where feasible; retain build failures, missing services and unknowns. Refine vulnerability locations beyond patch-context proxies with external evidence. Human adjudication remains absent because it was declined; do not imply it occurred.
3. **Known detection gaps:** custom parent-object authorization, sanitizer/normalization order, certificate-verification state, sandbox escape/resource exhaustion and cryptographic policy/identity cases in the new pilot remain unmodelled or lack source boundaries/context. General stored XSS remains weak.
4. **Cross-layer contribution:** evaluate real MCP/code links and show an incremental validated benefit with correlation disabled/enabled. Configuration association alone does not establish a security or review-time benefit.
5. **Operational reliability:** retain the two 120-second failures and the profiling diagnosis; use bounded post-fix smoke results only for the workload they measure. Larger repository/resource behavior, aggregate isolation limits and service durability need separate work.
6. **Broader platform coverage:** structured infrastructure/CI analysis, stronger JS/TS semantics, supported dependency ranges/provenance and broader AI/agent models need separate implementations and evaluations. Their roadmap status is not current detection coverage.
7. **Research claim and related work:** establish what the typed evidence/obligation/correlation approach adds over existing systems. Benchmark percentages and platform breadth alone do not establish novelty. No paper draft has been created.

The next milestone is a reproducible external study with verified oracles and a supported cross-layer or detection benefit. The broad platform can remain the product goal while the paper precisely states what its experiments demonstrate.
