# Matching-unit audit and bounded context experiment

Starting checkpoint `d5e148a0c7caa9fbf4c6317ac4711a798ab97f33`. The nine real validation cases are exposed. They are development material for any source-guided changes in this cycle; the final nine real test cases remain closed. Original metadata, previous exact-CWE results and errors are preserved.

Audit every declared location for psiTurk, OAuthLib, Starlette and Luigi using the cached pinned source and primary advisories. Separate patch locations from actual source/sink units. Record author/assistant rationale, upstream CWEs, proposed semantic CWEs, source/sink/guard lines, missing context and whether a patched negative is justified. This is not independent adjudication. Do not silently replace the original labels or calculate accuracy over all CVEs from revised units.

For Starlette, acquire only responses.py and types.py at the same two pinned source revisions, retaining byte hashes and acquisition errors. Compare the existing two staticfiles snapshots against the same snapshots plus these bounded package files under the old detector freeze `bb9fb30`. This is a declared six-file context experiment, not a full repository or runtime test. Added files are new validation/development exposure, not final-test exposure.

A justified detector increment may add resolved Flask/Quart template-source sinks, using original unsafe/safe tests, preserving template context variables as data. Freeze before reevaluating. The psiTurk proposed developer units are template-source arguments at vulnerable lines 384 and 410, and corresponding patched lines 384 and 411. Their semantic CWE is 1336; original metadata uses 77/78/94. Keep strict upstream matching separately. No unseen-real-code recall or paper-readiness claim follows from development gains.

Rerun exposed synthetic regressions and audited development snapshots, preserving added alerts, errors and negative controls. Do not implement corpus-name exceptions, automatically call patched archive helpers safe, execute target code or open the final test reserve. Findings outside audited units remain unadjudicated.
