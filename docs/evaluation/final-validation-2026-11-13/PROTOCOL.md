# Final real-code and operational evaluation protocol

13 November 2026. User authorized the final evaluation. Detector and all rules freeze: `4c166e0b179e1ff10a3a432e2bd439765b601a81`. Commit this protocol before retrieving any final-test source, patch body or advisory detail. All nine preassigned real test cases must remain represented, including unsupported categories, retrieval failures and label/hash errors. No detector or rule changes until outcomes are published. Later improvements require a fresh holdout.

## Labels and independence

Use the unchanged PatchEval-Verified external metadata and frozen source-function hashes as upstream labels. These labels originate outside Theron and predate this detector, but upstream repair roles do not make entire patched files clean or independently adjudicate Theron alerts. Fetch CVE records/advisory references independently of scanner output for all nine cases, preserving raw receipts and disagreement/unknown states. Assistant source review is explicitly author-side review; do not claim an independent human review occurred. Report upstream reference-span detection separately from semantic developer annotations. A second reviewer gate stays open if no independent reviewer participates.

## Static final test

Fetch only declared paths and full pinned revisions into a new cache. Verify original function hashes, retain raw byte hashes and input identity. No target code, setup script, archive, container or exploit executes. Run default Theron SAST on isolated files and grouped available files at each CVE/role/revision; normalize findings. Match only original CWE plus declared function span, excluding coverage notices. Preserve all raw alerts and parse errors. Label errors stay errors, never TN. Report vulnerable-reference case coverage, patched-reference alert cases, whole-file alert burden and unsupported limitations. Do not label patched-reference alerts automatically false positive or claim alert-level precision from this proxy.

Run pinned Bandit and Semgrep on exactly the same bytes when available, retain versions, rule hashes, failures/timeouts and native byte verification. Freeze the scoring adapter before collecting outcomes. Do not change labels or matching rules after seeing results. Publish grouped and isolated contexts without treating available-file grouping as a full repository.

## Operational tests

Use fresh subprocesses to scan three predefined sizes of the already exposed OWASP corpus (25, 100, 250 files, lexically first testcode Python files), three repeats each, a 120-second limit per worker and peak process memory. Include parsing, profiling, default SAST, normalization, correlation and JSON/HTML/SARIF generation. Record selected input bytes/hashes, runtime environment, raw times, empirical median/p95, failures, notices and deterministic finding fingerprints. Report first and later runs separately; do not claim OS-cold caches or multi-host generality.

Exercise the real in-process API queue with ten accepted jobs plus rejected overflow, one injected scanner failure, queue recovery, redacted errors, downloads and responsive health polling. This is an operational contract test with controlled transport, not a live GitHub/network or multiuser deployment load test. Preserve the user's earlier instruction not to launch the application. No live browser/server or application startup is required.

## Acceptance and publication boundary

Complete source/advisory receipts, all-case outcomes and errors, reproducible scripts, bounded runtime/memory measurements, operational contract checks, regression suites/build, accurate README/research update, synchronized branches through spideyctf and CI. Adverse outcomes must be published unchanged. Independent human adjudication, reviewer benefit, broad-platform completeness and production/load certification cannot be manufactured by an automated run and must remain open unless actually achieved.
