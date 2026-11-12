# Coverage repair and Step 6 delivery

The requested 60% recall milestone is met on both exposed OWASP validation and test splits. Implementation freeze: `fbcd818aa6f970e2f6d2595604f200b1596bd975`. This follow-up changes the detector, not the labels, splits, scoring adapter or denominator. All 1,230 cases and 14 categories remain included.

**These are exposed synthetic tuning regressions.** Prior outcomes and selected source templates, including validation/test templates, informed development. No unseen-project superiority, industry-grade accuracy or publication readiness is established. Reserved real-code validation/test source remains closed and independent real-code/edge adjudication remains pending.

## Measured improvement

| Exposed split | Before TP/FN/FP/TN | After TP/FN/FP/TN | Before recall | After recall | After precision | After F1 |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Development | 56/223/14/444 | 202/77/9/449 | 20.07% | **72.40%** | 95.73% | 82.45% |
| Validation | 0/84/1/163 | 77/7/0/164 | 0.00% | **91.67%** | 100.00% | 95.65% |
| Test | 14/75/5/151 | 65/24/6/150 | 15.73% | **73.03%** | 91.55% | 81.25% |

All final OWASP runs have zero parse/operational errors. Development gains 146 vulnerable matches, removes six fixed-case matches and adds one. Validation gains 77 vulnerable matches and removes one fixed-case match. Test gains 51 vulnerable matches and adds one fixed-case match. No previously detected vulnerable case becomes a miss. Full transitions are retained in [summary.json](summary.json).

Precision here means labelled-file/CWE case precision, not the proportion of individual alerts that are exploitable. All unmatched alert counts remain in the raw records. A request-to-session flow is review evidence, not proof of an authentication bypass; a weak-hash or insecure-cookie setting needs use/deployment context. These findings are medium confidence and their wording states those limits.

## What changed

- Imported instance methods now resolve their receiver in the caller's scope before entering the helper module. Original wrapper controls verify source provenance and the imports-disabled result.
- Base64 encoders/decoders and supported safe_join wrappers preserve input propagation. A safe_join result has a path-only boundary when the base has no observed input taint. It remains unsafe as shell text; symlinks, dependency-version vulnerabilities and filesystem races are outside this proof.
- Resolved hashlib MD5/SHA1 choices are reported as configuration evidence. Explicit `usedforsecurity=False`, strong algorithms, comments, unrelated imports and shadowed objects have negative controls.
- Selected non-cryptographic random APIs are tracked into session/cookie storage or a server-side store compared with a request cookie. Standalone simulation randomness and cryptographic generators do not produce this finding. Cookie comparison suggests a token context; authentication impact still requires review.
- Request-controlled session keys/values and explicitly disabled secure-cookie transport have bounded API models.
- SAX external-general-entity settings are tracked per parser instance into minidom parsing of request data. Default/disabled parsers and constant XML are negative controls.
- Elementpath expression arguments and resolved ldap3 search filters are modeled. Bound XPath variable values are separate from expression syntax; LDAP filter escaping is grammar-specific.
- Selected XPath quote exclusions protect only matching quoted literals. Construction-time snapshots prevent later reassignment from retroactively sanitizing an already-built query. Unquoted expressions, the other quote delimiter, limited replacement and repr formatting remain unsafe controls.
- Explicit shell vectors such as `['sh','-c',request_value]` are modeled even with `shell=False`, including supported equal-length platform branches. Ordinary executable arguments and positional data after a fixed shell command remain negative controls.

No corpus case IDs, names, labels or expected outcomes are used by detector logic. No scanned application or payload was executed.

## Pinned baseline comparison

These are Step 5's corrected exact-byte Bandit 1.9.4 and Semgrep CE 1.185.0 results, reused without rerunning either baseline. Their inputs, adapter and pinned configurations are unchanged. [Step 5 provenance, pins and staging correction](../step5-2026-11-13/README.md) remain the source of record; canonical result hashes are included in the new summary. Baseline support differs, and Theron's exposed outcomes informed this increment, so these numbers do not establish performance on unseen code.

| Split | Engine | TP | FN | FP | TN | Precision | Recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Development | Theron | 202 | 77 | 9 | 449 | 95.73% | 72.40% |
| Development | Bandit | 85 | 194 | 11 | 447 | 88.54% | 30.47% |
| Development | Semgrep | 49 | 230 | 31 | 427 | 61.25% | 17.56% |
| Validation | Theron | 77 | 7 | 0 | 164 | 100.00% | 91.67% |
| Validation | Bandit | 59 | 25 | 20 | 144 | 74.68% | 70.24% |
| Validation | Semgrep | 28 | 56 | 20 | 144 | 58.33% | 33.33% |
| Test | Theron | 65 | 24 | 6 | 150 | 91.55% | 73.03% |
| Test | Bandit | 63 | 26 | 47 | 109 | 57.27% | 70.79% |
| Test | Semgrep | 31 | 58 | 22 | 134 | 58.49% | 34.83% |

## Mechanism checks

Each ablation disables one feature against the same final implementation and split. All reports are retained, including neutral results.

| Split | Default TP/FP | No helper calls TP/FP | No local imports TP/FP | No sanitizer flags TP/FP |
| --- | --- | --- | --- | --- |
| Development | 202/9 | 182/9 | 182/9 | 202/42 |
| Validation | 77/0 | 70/0 | 70/0 | 77/1 |
| Test | 65/6 | 48/5 | 48/5 | 65/6 |

Helper calls/import resolution contribute 20, 7 and 17 vulnerable-case matches on development, validation and test respectively. These are overlapping feature effects, not additive contributions. Disabling sanitizers adds 33 development and one validation fixed-case match. These controls support the mechanisms on exposed synthetic inputs, not a generalization claim.

## Tuning benchmark and real development probes

PySASTBench remains **93 TP / 26 FN / 4 FP / 116 TN**, with one unresolved label retained as an error: 78.15% recall, 95.88% label-matched precision. The broader hash model increases fixed-file alerts from **8 to 17**, across **14 rather than 7 files**; alerts outside the label match increase from 4 to 13. The nine additional hash alerts are unadjudicated, so unchanged label-matched precision must not hide the extra review burden. [Full output](pysastbench.json).

The same seven exposed development CVEs / fourteen source snapshots were probed, with every declared function hash matching and zero probe errors. Default draft-target behavior remains the OpenDiamond vulnerable match with its patched snapshot quiet. Experimental redirect behavior remains provisional. This is not a real-world recall score: the sample lacks independent SAST-unit adjudication and some cases lack caller context. No reserved source was fetched or inspected. [Raw probe records](real-development.json) and the [independent worksheet](../step5-2026-11-13/INDEPENDENT-REVIEW.md).

## Remaining failures and next work

Validation still misses seven vulnerable cases: two session-boundary, four XML and one XPath. Test still misses twenty-four: seven deserialization, four command injection, seven LDAP and six code injection. All six fixed-case matches on test belong to code injection. Development still misses seventy-seven cases, especially paths and XPath. Dynamic factory/reflection dispatch, more complete mutation/alias models, broader XML APIs and general validators remain incomplete. The six test matches remain counted as false positives; no labels were changed to explain them away.

PySASTBench XSS recall remains 10%. Independent real-code and AI-specific evaluation, correlation-edge accuracy, reviewer benefit and operational scale remain unmeasured. These are the next research gates, after targeted development fixes under a new freeze. The untouched real-code test reserve should remain closed until independent labels and the final evaluation protocol are ready.

## Failure history and final freeze

The first full run at `1293b37` completed development but crashed during validation because a dynamic session key placed `None` in internal literal-state keys. This was an operational failure, not a zero-error result or a true negative. Commit `1dfcb62` fixes that state handling with an original regression and completed all splits: 202/77/65 TP.

A subsequent precision check of the already-exposed real development sample found that propagating safe_join uniformly also flagged its patched path flow. Commit `fbcd818` adds its path-only boundary, trusted-base and cross-grammar controls. All final defaults, nine ablations, PySASTBench and fourteen real development probes were rerun at that final freeze. OWASP counts remained unchanged. This sequence and post-outcome correction mean the increment must be treated as tuning, even though the final implementation is pinned.

## Reproduction and engineering checks

Use Python 3.12, the pinned datasets from the original studies, the same cached fourteen development snapshots and the repository's development dependencies. Do not run corpus applications or install their dependencies. From the repository root:

```powershell
.venv/Scripts/python.exe -m scripts.evaluate_coverage_increment
.venv/Scripts/python.exe -m pytest tests -q
cd frontend
npm test
npm run build
```

The evaluator accepts `--dataset`, `--pysastbench`, `--real-cache` and `--output`. It rejects detector/rule changes against the freeze, checks reserve metadata, verifies corpus hashes through the unchanged adapter, retains errors and case transitions, and writes canonical JSON artifact hashes. The underlying PySASTBench CLI returns exit 1 for its unresolved label; the combined evaluator retains that error in its output rather than dropping the case.

Local checks: **472 Python tests passed**, with one existing dependency deprecation warning; **11 frontend tests passed**, and the TypeScript/production build passed. The app was not started and live UI behavior was not manually rechecked. Earlier end-to-end export/UI controls remain in the regression suite. Step 6 delivers this reproducible checkpoint and updated README/quality/research documents; it does not close the independent research gate.

Model references: [Python hash security flag](https://docs.python.org/3/library/hashlib.html), [random security considerations](https://docs.python.org/3/library/random.html), [SAX defaults and entity feature](https://docs.python.org/3/library/xml.sax.html), [LDAP filter escaping](https://ldap3.readthedocs.io/en/latest/searches.html), [Werkzeug path-name boundary](https://werkzeug.palletsprojects.com/en/stable/utils/), [Flask cookie security](https://flask.palletsprojects.com/en/stable/web-security/).
