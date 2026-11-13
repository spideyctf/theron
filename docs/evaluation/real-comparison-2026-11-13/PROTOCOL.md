# Real-code validation comparison protocol

Starting checkpoint `58151ac0b4cfd26ab21b643998f8d75ea2f26f40`; detector remains frozen at `bb9fb3092011aec3c5de0af4b28dea9fdc2b4715`. No detector changes are part of this evaluation. The nine validation cases and their source are already exposed; the nine final test cases remain closed.

Use every one of the 28 pinned validation snapshots from the previous exposure ledger. Preserve exact bytes and original function hashes. Run Theron in both isolated-file mode and grouped mode: each CVE/role/revision group supplies all available declared files with original repository-relative paths. This adds available multi-file context, not a complete repository or installed dependencies. Keep projects, roles and revisions separate.

Run pinned Bandit 1.9.4 and Semgrep CE 1.185.0 with the same Python rules revision/configuration as Step 5 on the same 28 files. Keep all severities/confidences, unmatched alerts and scanner errors. Independently verify native Linux staged file/rule hashes before Semgrep. Reuse the established CWE normalization; compare same-CWE reported start lines inside the original declared function spans. This reference match is not a confirmed vulnerability, and a quiet fixed file is not a true negative. Never report real-world precision/recall without adjudicated units.

Keep the two original function-hash failures as label errors for all tools, even though tools can scan the raw files. As a separate diagnostic only, check whether the exact frozen function hash can be found at another AST function span; do not rewrite the original labels, silently rescore or change the detector. Record available local-import resolutions and missing context to distinguish this experiment from whole-repository analysis.

Publish per-file alerts, per-case reference matches, input/rule hashes, errors, grouping/import coverage and interpretation. No target modules, dependencies, setup scripts, applications, exploits, launch commands or live credentials are executed. No independent adjudication, novel findings or tool superiority is implied by these probes.
