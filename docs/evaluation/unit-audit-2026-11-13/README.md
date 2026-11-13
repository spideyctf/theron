# Matching-unit audit and first real-code development gain

13 November 2026. Starting checkpoint `d5e148a`; new detector frozen at `54110a461b770cc2734585475381a4c99362b1b9`. This cycle audits four exposed validation cases, adds a bounded template-source model and tests additional package context. Source-guided changes make these cases development material for this increment. **The final real test reserve remains closed.**

## What the audit changed

| Exposed case | Audit finding | Evaluation consequence |
| --- | --- | --- |
| psiTurk, CVE-2021-4315 | Request mode is inserted into template source before render_template_string; the patch passes mode through context instead | Two provisional unsafe-source units and two corresponding patched-flow units use semantic CWE-1336; original metadata's 77/78/94 remains unchanged |
| OAuthLib, CVE-2022-36087 | The changed code is an IPv6 regex; the project's advisory describes denial of service | Do not treat that constant as an open-redirect sink simply because reserved metadata says CWE-601 |
| Starlette, CVE-2023-29159 | Changed span is the lookup_path containment guard; FileResponse is outside it | Guard line 172 and serving sink line 192 need distinct units, with ASGI/callback/tuple/member context |
| Luigi, CVE-2024-21542 | Vulnerable functions extract archive members; the patched helper still uses commonprefix before extractall | A patched role is not automatically a clean negative; a sibling-path counterexample shows the guard's lexical limitation |

[audit.json](audit.json) records original locations/hashes, proposed units, missing context and rationale. This is developer/assistant review, not independent adjudication. The Luigi counterexample uses only original path strings and pure path operations; it neither extracts an archive nor proves deployed exploitability. No original metadata or prior score was edited.

Primary evidence: [psiTurk patch](https://github.com/NYUCCL/psiTurk/commit/47787e15cecd66f2aa87687bf852ae0194a4335f), [OAuthLib advisory](https://github.com/oauthlib/oauthlib/security/advisories/GHSA-3pgj-pg6c-r5p7), [Starlette advisory](https://github.com/advisories/GHSA-v5gw-mw7f-84px), [Luigi issue](https://github.com/spotify/luigi/issues/3301), and the pinned source receipts. These support source interpretation; they do not independently validate every SAST unit or negative label.

## General detector increment

The new PY-SAST-SSTI-001 model reports input/model text reaching the template-source argument of resolved Flask/Quart render_template_string calls, including aliases and source keywords. Context variables are data, not template source. HTML escaping does not make template syntax safe. Original controls cover constants, context variables, shadowing/unrelated imports, clean overwrites, helper-return propagation, imported helpers and the imports-disabled result.

The rule produces CWE-1336 with a source/sink trace. It participates in the existing bounded MCP declaration-to-flow association without adding vulnerability counts or runtime-exposure claims. An original integration control verifies that the same finding and trace support the relationship. No corpus identifier, expected label or project-name special case enters detector logic. [Flask API reference](https://flask.palletsprojects.com/en/stable/api/#flask.render_template_string).

## Audited psiTurk observations

| Developer-audited source unit | Old detector bb9fb30 | New detector 54110a4 |
| --- | ---: | ---: |
| Vulnerable advertisement renderer, line 384 | No template-source finding | Source 328 → sink 384 |
| Vulnerable consent renderer, line 410 | No template-source finding | Source 406 → sink 410 |
| Patched advertisement renderer, line 384 | No template-source finding | Quiet for this flow |
| Patched consent renderer, line 411 | No template-source finding | Quiet for this flow |

The increment detects **two audited flows in one published, exposed CVE**, with the two corresponding patched flows quiet. Disabling interprocedural analysis removes both vulnerable matches; the patched flows remain quiet. These are provisional developer units selected after source inspection, not an unseen real-code accuracy result or 100% general recall. Runtime exploitation was not attempted. All other previously exposed validation files are rerun and retained; two unrelated weak-hash advisories remain in ChuanhuChatGPT. The two original function-hash errors are retained as unresolved labels, not repaired by relabelling.

The original strict metadata matcher would not credit CWE-1336 against exact 77/78/94 metadata. That older report stays preserved, while this separate audit explains the mismatch. Baseline location observations reuse the previous identical psiTurk bytes: Semgrep's render-template-string candidates occur at all four audited renderer locations and retain their reported CWE-96; Bandit has no alert at these four sinks. No baseline CWE was silently remapped and no new baseline accuracy percentage is claimed. [Raw observations](baseline-unit-observations.json).

## Bounded Starlette context experiment

Only responses.py and types.py were added at the original two Starlette revisions: **four new package files**, with pinned hashes and acquisition errors recorded in [context-exposure.json](context-exposure.json). The connector could not read those old paths; immutable raw URLs supplied the files. They are ignored-cache source data, not redistributed code.

Each role is scanned as staticfiles.py alone and then with its own two package files. Under the old detector, both modes emit no findings; under the new freeze, the package-context probes also emit none. This adverse outcome is retained in [context-before.json](context-before.json) and [context-after.json](context-after.json).

The existing engine does not yet connect the typed ASGI scope through the anyio callback, lookup tuple, containment guard and serving method. Adding package files alone does not supply these semantic models. This is a six-file bounded experiment, not a full-repository scan or demonstrated context benefit. It identifies the next concrete development gap without opening final-test source.

## Regression metrics

All exposed synthetic scores remain unchanged. Original labels, files and adapters are preserved.

| Dataset/split | Precision | Recall | F1 | TP / FN / FP / TN |
| --- | ---: | ---: | ---: | --- |
| OWASP development | 95.73% | 72.40% | 82.45% | 202 / 77 / 9 / 449 |
| OWASP validation | 100.00% | 91.67% | 95.65% | 77 / 7 / 0 / 164 |
| OWASP test | 100.00% | 73.03% | 84.42% | 65 / 24 / 0 / 156 |
| PySASTBench | 95.88% | 78.15% | 86.11% | 93 / 26 / 4 / 116 |

OWASP has zero operational errors; PySASTBench retains its one unresolved vulnerable label. Fixed-file alert volume remains 17 across 14 PySASTBench files, including 13 outside labelled matches. No new clean-file success was inferred from the additional real-code files. These regressions do not establish independent real-world precision.

## Reproduction and remaining work

With the existing pinned corpora and validation cache, run from the trusted repository root:

```powershell
.venv/Scripts/python.exe -m scripts.evaluate_audited_units --fetch-context
.venv/Scripts/python.exe -m pytest tests -q
```

The evaluator rejects changed detector/rules, original metadata, frozen audit/context selections, unit source hashes or cache paths. Its optional fetch flag retrieves only the four predeclared package files and verifies bytes. --skip-synthetic reruns only the audited real development/context probes. No scanned code, setup script, renderer, archive, declared launch command or exploit is executed. Source bytes remain in ignored caches; JSON results, source receipts, audit, ablation and canonical artifact hashes are published.

**513 Python tests pass**, including template safety, provenance, correlation and evaluation-unit identity controls. Frontend behavior uses the existing finding/evidence format and is covered by delivery CI. The app was not started.

Next: model and test ASGI/callback/tuple propagation against original controls; audit archive-member sources and containment without trusting the patched role; investigate regex/category and remaining hash metadata issues; then freeze again for a suitable evaluation. Independent accuracy, whole-repository coverage, real MCP-edge correctness and reviewer benefit remain unmeasured. This checkpoint is a real-code development improvement, not publication readiness or a new holdout result.
