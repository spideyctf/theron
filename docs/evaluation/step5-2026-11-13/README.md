# Step 5 evaluation checkpoint

13 November 2026. Implementation frozen at `36ee9eef341b561cb79f8f1c2edfbd9c7533187f`. The detector, correlation pass, rules, labels and split assignments were unchanged during evaluation. The [protocol](PROTOCOL.md) was written before fresh outcomes. The app and target applications were not started.

Read [RESULTS.md](RESULTS.md) for tables and failure analysis, [summary.json](summary.json) for metrics, [environment.json](environment.json) for implementation/tool pins, and [input-provenance.json](input-provenance.json) for exact input/rule byte hashes. [Installed distribution versions](distribution-pins.json) are recorded without credential-bearing direct URLs. [Canonical artifact hashes](artifact-hashes.json) survive checkout line-ending changes; these are artifact integrity records, not independently validated labels.

## What was evaluated

- All **1,230 previously exposed OWASP cases across 14 categories**, with five shared helpers per split: 737 development, 248 validation, 245 test. Each split ran default Theron and three feature ablations. These are exposed regressions, not fresh holdouts.
- Fresh **Bandit 1.9.4** and **Semgrep CE 1.185.0** baselines on the exact same staged source bytes. Semgrep used the pinned Python rules at `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2`: 378 configured rules, 371 applicable. Coverage was checked for all 742/253/250 split files and all 14 development snapshots. Baseline raw source snippets remain ignored; derived metadata, raw report digests, errors and unmatched-alert counts are published.
- The same **seven real-code development CVEs / 14 snapshots**, with default/experimental probes, three ablations and component baselines. Four pairs have draft target sink locations; three require more matching/caller context. All seven remain represented. No independently validated precision/recall denominator exists.
- **Nine original correlation controls**, enabled/disabled on identical inputs/findings, with one warm-up and 30 timings per mode/case. The pass changes relationships, not vulnerability counts. Bandit/Semgrep graph scores are not applicable.
- The existing PySASTBench tuning regression: **93 TP / 26 FN / 4 FP / 116 TN**, one unresolved label. Recall 78.15%, precision 95.88%, F1 86.11%. Exit code 1 retains that error. It remains tuning evidence.

## Main findings

| Exposed OWASP test | TP | FN | FP | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Theron | 14 | 75 | 5 | 151 | 73.68% | 15.73% |
| Bandit | 63 | 26 | 47 | 109 | 57.27% | 70.79% |
| Semgrep CE | 31 | 58 | 22 | 134 | 58.49% | 34.83% |

Theron validation recall remains **zero**. Both baselines detect more vulnerable test cases. Lower fixed-case matches at lower coverage do not establish superiority. Synthetic template-family intervals are descriptive; few clusters and shared helpers limit independence.

Helper/import ablations each lose two development detections, and disabling sanitizer models adds eight development fixed-case matches. All three are neutral on exposed validation/test. In the real development probe, removing helper calls loses the existing OpenDiamond match; neutral sanitizer ablation is not evidence that its patched wrapper is correctly modelled.

An [original failure control](failure-probes.json) demonstrates missing `safe_join` return propagation into a shell sink. The patched file's quiet result cannot be credited to explicit sanitizer handling. This is a future detector fix; the frozen implementation was not changed to improve these results.

## Corrected baseline provenance

The old Windows staging added carriage returns to baseline copies. All **742 development files** differ in raw bytes but agree after the documented newline diagnostic. A same-tool/same-rules replay on the old stage reproduces the old Semgrep development result (42 TP / 29 FP); exact-byte staging produces 49 TP / 31 FP. Nine case outcomes change. All other OWASP engine/split case outcomes remain unchanged.

[The diagnostic](staging-diagnostic.json) preserves the old-stage replay, corrected result and changed cases. Older published artifacts remain intact. The primary comparison uses exact corpus bytes, not whichever stage produces a preferred score. Old line-level provenance is not validated by unchanged file/CWE totals. Bandit ran on Windows and Semgrep in WSL; tool wall times were not measured per split and no speed ranking is made.

## Independent review still required

The **nine real validation and nine real test candidates remain closed**. No new target source was downloaded. There are **zero independently adjudicated real-code cases or MCP edges**, and no reviewer-time benefit has been measured.

Give an independent reviewer [the worksheet](INDEPENDENT-REVIEW.md) and [output-blinded JSON packet](independent-review-packet.json). Keep [the upstream-role key](review-key.json) and tool outcomes separate until initial annotations are recorded. This omits outputs; it is not a double-blind study. The reviewer must identify source, sink, CWE, guards, eligibility and matching unit, mark missing context unknown, and disclose prior output/patch exposure. Store completed annotations as a new artifact; preserve the pending templates.

## Reproduction

Use the already pinned OWASP/PySASTBench datasets and the 14-source development cache from Step 3. Install pinned baseline versions in isolated environments and fetch the separately licensed rules as described in [the earlier baseline protocol](../owasp-2026-11-12/README.md). No target dependencies, images, setup scripts or exploits are needed. Rules are used for local evaluation only and are not bundled into Theron's detectors/service.

Use a **new empty cache and output directory** for another run:

```powershell
python -m scripts.evaluate_step5 stage --cache NEW_CACHE --output NEW_RESULTS
python -m scripts.evaluate_step5 theron --cache NEW_CACHE --output NEW_RESULTS
```

The stage writes exact source/rule bytes and an archive. Unpack `NEW_CACHE/inputs.tar` into a new native Linux directory using `tarfile.extractall(..., filter="data")`, then verify every `input-sha256.json` entry before scanning. The published run verified **1,596 input/rule files**. Preserve the `owasp/SPLIT`, `realcode` and `rules/python` directory structure.

For each development/validation/test directory and the realcode directory, run:

```text
python -m bandit -r INPUT -f json -o NEW_CACHE/bandit-SPLIT.json --ignore-nosec --exit-zero
semgrep scan --config NATIVE_STAGE/rules/python --metrics=off --disable-version-check --no-git-ignore --no-rewrite-rule-ids --timeout 10 --jobs 2 --json --output NEW_CACHE/semgrep-SPLIT.json INPUT
```

Use `realcode` as SPLIT for the development-source baseline. The published run used native WSL paths for Semgrep, with output copied into the Windows cache. Then:

```powershell
python -m scripts.evaluate_step5 collect --cache NEW_CACHE --output NEW_RESULTS
python -m scripts.evaluate_step5 controls --cache NEW_CACHE --output NEW_RESULTS
python -m scanner.benchmark --dataset .benchmark-cache/PySASTBench --output NEW_RESULTS/pysastbench-regression.json
python -m scripts.summarize_step5 --directory NEW_RESULTS
python -m pytest tests -q -p no:cacheprovider
```

Collection verifies inventory coverage and retains errors; incomplete scans do not become clean negatives. The old-stage replay is an optional provenance diagnostic, excluded from the primary comparison. Preserve/copy its measured diagnostic only if actually replayed and verified. New tool JSON timestamps/paths/timings can differ; case outcomes, inputs, configuration and uncertainty are the reproducibility targets.

`collect` checks the Bandit environment version and Semgrep report version. On Linux, pass `--bandit-python PATH_TO_PINNED_ENV/bin/python`. The real development comparison deliberately matches reported start lines to prior draft sink lines; available end lines are retained for human review. This is not a validated cross-tool span-matching protocol and must not be interpreted as baseline false-negative rates.

Step 5's automated engineering evaluation is complete. The independent real-code/edge and publication research gate remains open. No detector fixes were mixed into evaluation, no validation/test real source was unblinded, and no accuracy or industry-readiness claim is inferred from passing tests.
