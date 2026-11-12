# Step 3: development source review and bounded detector increment

12 November 2026. Starting checkpoint: `487e207d3582656a99c0e30b2f318edfba01f075`. The [Step 2 manifest](../realworld-2026-11-12/manifest.json) and its assignments remain unchanged. This checkpoint records development evidence; it is not independent real-world accuracy or an industry-readiness claim.

## Selection and source review

Before source inspection or baseline runs, select **every development case tagged CWE-601, CWE-22 or CWE-918**: seven CVEs across five projects. [selection.json](selection.json) preserves the IDs. No validation/test or development-only target source was opened. We fetched seven pinned patch commits and 14 full-file source snapshots, then checked all **18 declared vulnerable/fixed function spans** against the frozen snippet hashes. Every span matched.

The [review ledger](review.json) records exact revisions, patch URLs, span hashes, proposed target sinks, root causes, exposure and unresolved context. These are **assistant-reviewed drafts awaiting an independent human reviewer**. There are still **zero independently adjudicated/scorable real-world cases**. No application imports, target execution, images or exploits were used. No target source is redistributed here.

| Development case | Source/patch interpretation | Probe outcome |
| --- | --- | --- |
| [CVE-2019-10856](https://github.com/jupyter/notebook/commit/979e0bd15e794ceb00cc63737fcd5fd9addc4a99) | Login redirect URL/origin parsing bypass | Missed; imported handler hierarchy and branch semantics unresolved |
| [CVE-2020-10691](https://github.com/ansible/ansible/commit/b2551bb6943eec078066aa3a923e0bb3ed85abe8) | Archive-manifest filename escapes extraction directory | Missed; archive stream/manifest and multi-helper flow unsupported |
| [CVE-2020-26215](https://github.com/jupyter/notebook/commit/3cec4bbe21756de9f0c4bccf18cf61d840314d74) | Repeated leading slashes survive URI trimming into a redirect | New experimental match at vulnerable line 862; also flags patched line 867 |
| [CVE-2021-21354](https://github.com/mozilla/PollBot/commit/6db74a4fcbff258c7cdf51a6ff0724fc10c485e5) | aiohttp path trimming retains external-redirect syntax | Missed; unannotated middleware callback request type unresolved |
| [CVE-2022-31506](https://github.com/cmusatyalab/opendiamond/commit/398049c187ee644beabab44d6fece82251c1ea56) | Flask path parameter flows through path helper to send_file | Already detected at vulnerable sink line 137; corresponding patched flow quiet |
| [CVE-2024-0243](https://github.com/langchain-ai/langchain/commit/bf0b3cc0b5ade1fb95a5b1b6fa260e99064c2e22) | URL string-prefix boundary accepts a sibling authority | Missed; helper returns links, and outbound-request/caller context is absent |
| [CVE-2024-3571](https://github.com/langchain-ai/langchain/commit/aad3d8bd47d7f5598156ff2bdcc8f736f24a7412) | Library key permits an absolute/traversing file-store path | Missed; untrusted application caller and collection/class flows unresolved |

Interpretation is based on the pinned code, patch and patch-test changes. It does not prove application reachability or completeness of any patch. The merge patch for CVE-2020-26215 is compared with the **explicit declared vulnerable snapshot**, not an arbitrarily selected parent.

## Changes and precision gate

- Resolve local transitive Tornado RequestHandler inheritance and request URI/path/body/header sources. Keep local overrides and shadowed methods from being mistaken for native framework methods.
- Recognize path/URL fields of explicitly typed aiohttp Request parameters; untyped names alone remain insufficient.
- Preserve taint through partition/rpartition unpacking, including starred targets, while keeping literal separators clean. This is conservative propagation, not exact tuple-value modeling.
- Read the actual redirect destination argument: Flask/Quart `location`, Django `to`, and Starlette/FastAPI/Tornado `url`. Status/reason fields do not become destinations.
- Add medium-confidence **experimental** Tornado/aiohttp redirect candidates, passed through the existing SAST opt-in flag. Original fixtures cover unsafe/safe destinations, shadowing, overrides, typed/untyped requests and source/sink evidence.

The new redirect candidate also fires on upstream's slash-normalized patched Jupyter code. We retain this adverse outcome and **do not promote that rule to default vulnerability reporting**. Removing slashes does not become a universal URL sanitizer. Origin validation, query-only influence, browser backslash semantics and normalization need further modeling/review. Two other experimental alerts at lines 912/917 are outside the labelled function, in a configured redirect with appended query input; they are unadjudicated and cannot be counted as true positives.

## Before/after probe

Both modes scanned the same 14 full-file texts independently, without application harnesses or cross-file imports. All source hashes match across [before.json](before.json) and [after.json](after.json); the probe also pins each detector source hash. No parse/budget notices or file/hash errors occurred. Counting only the manually proposed target flows above:

| Mode | Vulnerable snapshots with a target match, before → after | Patched snapshots with a target match, before → after |
| --- | ---: | ---: |
| Default | 1/7 → 1/7 | 0/7 → 0/7 |
| Experimental enabled | 1/7 → 2/7 | 0/7 → 1/7 |

These are development-probe counts, **not validated recall/precision**. The two out-of-target experimental alerts remain in the raw records. The OpenDiamond labelled helper span omits the actual send_file sink; source/caller context is needed to establish the candidate matching unit. No case was removed, relabelled clean or promoted to an independent denominator.

## Existing tuning-corpus regression

Default PySASTBench, same pinned corpus and scoring adapter: **93 TP / 26 FN / 4 FP / 116 TN**, one unresolved vulnerable label. Recall **78.15%**, precision **95.88%**, F1 **86.11%** over 239 scorable variants. The previous checkpoint had 92 TP / 27 FN with identical FP/TN. Only `89_DS-18` vulnerable changed (FN → TP), through inherited Tornado request-body JSON into a SQL string. SQL recall is now 19/20; parameterized SQL controls remain quiet. This previously inspected corpus is tuning evidence.

[Raw regression output](pysastbench-regression.json) retains the unresolved label, all case hashes and unrelated fixed-file alerts. Expected benchmark exit code **1** preserves that label error. No new OWASP validation/test run was used for detector tuning; its older published numbers remain attached to its frozen detector, not this increment.

## Reproduction and next gate

Use Python 3.12. Fetch only the pinned development source URLs recorded in the ledger into `.benchmark-cache/realworld-step3/CVE/ROLE/REPOSITORY_PATH`; retain the exact line spans and UTF-8 text. Then run:

```powershell
python -m scripts.probe_realworld_development --manifest docs/evaluation/realworld-2026-11-12/manifest.json --selection docs/evaluation/development-2026-11-12/selection.json --cache-root .benchmark-cache/realworld-step3 --output .benchmark-cache/realworld-step3/recheck.json
python -m scanner.benchmark --dataset .benchmark-cache/PySASTBench --output .benchmark-cache/realworld-step3/pysastbench-regression.json
python -m pytest tests -q -p no:cacheprovider
```

The probe rejects reserved selection IDs, duplicate selections, path escapes and mismatching declared snippet hashes, and records unavailable files as errors. Whole-file UTF-8/LF hashes must equal the published snapshots to compare results. It is a raw static-file probe, not the final research SAST adapter.

To reproduce the baseline, create a detached worktree at `487e207`, use that as the working directory, and run this checkpoint's probe script through `python -c "import runpy; runpy.run_path('ABSOLUTE_PATH_TO_PROBE_SCRIPT', run_name='__main__')"`, passing absolute manifest/selection/cache/output paths. This imports the baseline detector from that worktree; verify its recorded hash against before.json. The virtual environment can be shared; no target packages need installation.

The engineering increment and draft audit are delivered. Independent label review, a sufficient source-to-sink matching protocol, richer caller context and redirect precision remain open B02 acceptance items. Do not claim B02's research gate or paper readiness is complete. Step 4's correlation pilot has not started.
