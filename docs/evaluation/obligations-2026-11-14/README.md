# Authorization, JWT and HTTP framing: implementation and evaluation

14 November 2026. Scanner freeze **`8c10fdbc904ef9323d00134878f5b2c6ed0097d0`**; candidate registration **`d7639d4`** preceded both detector implementation and target-source inspection. This is an engineering/evaluation report, not a manuscript or a publication-readiness certification.

## What shipped

- Declared DRF object-permission policies: bounded paths track lookup identity, aliases, the request subject and checks before returning an object or supported serialization. Authentication-only policies do not imply object authorization. Wrong-object checks retain their locations. Dynamic policies, custom hooks, unresolved objects and path exhaustion produce review notices where recognized.
- JWT call boundaries: disabled signature verification, externally derived algorithm selection, known public-key material used with HMAC, and mixed symmetric/asymmetric allowlists. Missing or unknown algorithm settings alone do not become vulnerabilities. Library rejection and deployment reachability remain explicit uncertainties.
- HTTP chunk footers: resolved h11 buffer/event contracts identify delimiter state. Consuming those bytes based only on length produces a candidate; matching CRLF or the remaining fragmented prefix before advancing state is recognized. This does not model every HTTP parser or grammar.
- Structured `obligation` evidence carries the required condition, observed action, assumptions and related locations through JSON, SARIF, standalone HTML, API JSON/SARIF downloads and frontend details. These candidates are advisory, not automatically confirmed exploits or fabricated source-to-sink traces. Existing observed MCP correlation does not absorb them.

**658 Python tests, 15 frontend tests and production frontend build passed.** Fifty-three added Python tests cover unsafe/safe/unknown controls and delivered evidence. Fifty were committed with the scanner freeze; three later CLI export tests reuse the original inert fixture and do not tune against external cases. Target fixtures stay inert. The user application was not launched.

## Six preregistered external candidates

Selection was purposive and informed by CVE advisory metadata, not random. All six were absent from the previous real-code manifest. Source was opened only after the scanner freeze; no detector tuning followed that exposure. Upstream repair roles and author-derived function units do not constitute independent human ground truth. A repaired revision is not globally clean.

| Candidate | Automatic static result in the declared mechanism unit | Bounded runtime evidence |
| --- | --- | --- |
| [CVE-2026-82411, open-object](https://github.com/maykinmedia/open-object/commit/11c5b85ea5d1d80f940883f01b8b8ea80ccdd47c) | Missing object-check candidate at vulnerable return; repaired unit quiet | Exact method body with substitute helpers returns data before repair and invokes the denying helper after repair. Author-derived adapter; real DRF policy/database/routing not exercised |
| [CVE-2026-58373, CVAT](https://github.com/cvat-ai/cvat/commit/27953f19d2265f8b495369f816730a7452db791b) | Miss: parent-object authorization in `get_queryset` and custom policy machinery exceed v1. An unrelated unresolved-policy notice remains on each revision | Not run: upstream service/database/account fixtures unavailable; inconclusive |
| [CVE-2024-33663, python-jose](https://github.com/mpdavis/python-jose/commit/12f30c8c87b343ad4f9e27e8b5b9e0ef7d665cb3) | Miss: internal key-format rejection logic exceeds JWT call-site models | Author-derived ECDSA OpenSSH/HMAC adapter accepts forged claims before repair, rejects afterward; legitimate HMAC control passes both |
| [CVE-2022-39227, python-jwt](https://github.com/davedoesdev/python-jwt/commit/88ad9e67c53aa5f7c43ec4aa52ed34b7930068c9) | Miss: signed/returned payload identity and compact/JSON format confusion are unmodelled | Adapter derived from maintainer regression accepts forged subject before repair, rejects afterward; legitimate signed token passes both. Original PyVows suite not executed |
| [CVE-2022-24761, Waitress](https://github.com/Pylons/waitress/commit/9e0b8c801e4d505c2ffc91b891af4ba48af715e0) | Miss: numeric and chunk-extension grammar validation differs from footer validation | **Unmodified upstream** `TestChunkedReceiverParametrized`: vulnerable 10 failed / 3 passed; fixed 13 passed. Failures include changed rejection details and are not ten demonstrated exploit acceptances |
| [CVE-2024-1135, Gunicorn](https://github.com/benoitc/gunicorn/compare/21.2.0...22.0.0) | Miss: transfer-coding combinations and header interpretation exceed footer model | Author-derived unsupported transfer-coding combination accepted in affected tag and rejected in fixed tag; ordinary chunked control passes both. A mechanism replay, not the original reporter's full deployment reproduction |

Summary: **1/6 vulnerable cases has an automatic obligation candidate; 0/6 repaired mechanism units does.** This is a disclosed advisory/function-unit proxy, not a real-world recall/precision estimate. **Strict CNA-CWE plus function-span matching finds zero cases among the five with CNA CWE labels; python-jose has no CNA CWE and remains unscorable under that rule.** In particular, open-object's CNA label is CWE-639 while Theron's authorization candidate is CWE-863: the semantic observation is not a strict label match. [Label corroboration](label-corroboration.json). Across the 28 application source snapshots there are one medium candidate and two informational notices, zero parse errors. All five semantic misses remain in the denominator. Disabling authorization obligations removes the one candidate; crypto/protocol ablations add no fresh-case distinction. [Raw default result](default.json), [ablations](static-summary.json).

`source-plan.json` records exact affected/fixed revisions. python-jose and Gunicorn use pinned affected/fixed tags rather than minimal adjacent repair commits, so unrelated version differences remain a threat to causal attribution. The other pairs use the repair commit and its first parent. Source context is the available registered files, not whole-repository analysis. Windows command-length retrieval failures were recovered and retained; the new python-jwt test is correctly absent from its earlier parent. These are not scanner errors or safe results. [Receipts](source-receipts.json), [runtime package receipts](runtime-source-receipts.json).

## Controlled verification and its limits

The matched baseline replay covers the **same 28 application files** with verified exact bytes: Bandit 1.9.4 emits **17 alerts**, Semgrep CE 1.185.0 with pinned Python rules emits **12**, both with zero reported errors. Neither emits an alert in the specifically declared mechanism functions. Full-file alerts remain in [the baseline report](baselines.json); totals and location overlap are not semantic vulnerability accuracy. This small, purposive proxy does not establish tool superiority. The first Semgrep attempt blocked on Windows-mounted filesystem I/O and was interrupted; the successful replay used a hash-verified native WSL stage with a 180-second wall bound. [Attempts](baseline-attempts.json), [native byte verification](baseline-native-verification.json).

[Runtime results](runtime.json) retain all six attempts. Four author-derived adapter pairs and one upstream test pair distinguish the revisions under their stated conditions. CVAT remains unrun. The first two Gunicorn attempts failed on missing context modules, were preserved in `runtime-attempt-1.json` / `runtime-attempt-2.json`, and were rerun after retrieving hash-pinned missing files. `runtime-attempt-3.json` preserves the first successful adapter before adding legitimate-input controls and stricter temporary-storage bounds. No failed attempt was counted as a negative vulnerability label.

Target code ran only inside disposable, capability-dropped WSL/bubblewrap namespaces with environment clearing, no host home or Windows drives, no runtime network, read-only target/dependency/harness mounts, 16 MiB temporary storage, a 30-second wall deadline, per-process 15-second CPU/1 GiB address-space limits, process limit 64, 1 MiB output-file limit and 64 KiB returned output. The isolation probe saw neither host path and obtained network-unreachable errno 101. Dependency wheel hashes are locked in `runtime-dependencies.json`; harness hashes and commands are recorded. Downloading/extracting wheels does not execute installation/build hooks or `.pth` files on the host. Docker's engine was unavailable.

This runner shares the WSL kernel, has no aggregate cgroup memory/CPU quota, and is not a hardened multi-tenant verification service. Limits are per process where stated. Adapter success does not validate the full application, deployed exploitability or the scanner's detection of that behavior. In particular, successful crypto/protocol replays **do not repair their static misses**.

## Exposed regression and operational evidence

All **1,470 synthetic variant outcomes and alert counts remain unchanged** from the preceding library-flow increment. These corpora and outcomes were already exposed during tuning.

| Corpus/split | TP | FN | FP | TN | Recall | Precision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| OWASP development | 202 | 77 | 9 | 449 | 72.40% | 95.73% |
| OWASP validation | 77 | 7 | 0 | 164 | 91.67% | 100.00% |
| OWASP test | 65 | 24 | 0 | 156 | 73.03% | 100.00% |
| PySASTBench | 93 | 26 | 4 | 116 | 78.15% | 95.88% |

PySASTBench retains one unscorable vulnerable label and 17 fixed-file alerts across 14 files, 13 outside label matches. No individual-alert exploit precision follows from these case-level metrics. [Regression summary](synthetic-summary.json).

On **already exposed** original final-test source, the new footer check distinguishes vulnerable/patched h11. Signature-verification-disabled advisories also appear in both Planet revisions; they do not discriminate that CVE's fix. Existing configured Celery/MechanicalSoup observations remain. [Development replay](exposed-development.json). The original `4c166e0` **0/9 frozen reference result is preserved**, not rewritten by these later observations.

The pinned offline CLI smoke selected 275 files, read 273 and completed SAST/AI/agentic in **117.76 seconds wall time against a 120-second limit** (reported scan time 108.15 seconds). Three application notices retain tuple-shape and analysis-budget limits; twelve context findings include two oversized-file notices. SCA/network was excluded. This is one near-budget run, not a capacity claim or proof that this repository is vulnerability-free. [Operational result](offline-selfscan.json), [input hashes](offline-self-inputs.json).

## Reproduce

Use the declared scanner commit for detector replay; later documentation/harness commits leave `scanner/` and `rules/` identical. Install Theron's development/web dependencies and frontend lockfile first. Cached source is ignored and must be restored from the pinned receipts:

```powershell
.venv/Scripts/python.exe -m scripts.fetch_obligation_sources
.venv/Scripts/python.exe -m scripts.evaluate_obligations
.venv/Scripts/python.exe -m scripts.compare_obligation_baselines stage
```

For the baseline native stage, extract `.benchmark-cache/obligation-baselines/inputs.tar` to `/tmp/theron-obligation-baselines` in WSL using Python's `tarfile.extractall(..., filter='data')`. Verify the hashes with `python3 /mnt/d/TheLobe/sem7/theron/scripts/compare_obligation_baselines.py verify-native /tmp/theron-obligation-baselines`; run pinned Semgrep CE 1.185.0 with the flags in `baselines.json`, the staged `rules/python` configuration and staged `sources`, writing JSON to `.benchmark-cache/obligation-baselines/semgrep.json`. Then run `python -m scripts.compare_obligation_baselines compare`. Bandit is pinned to 1.9.4; rule checkout is `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2`. [Exact inputs](baseline-inputs.json). Do not substitute current registry rules.

For opt-in runtime replay, download the **exact wheel filenames/versions in the dependency lock**, with `pip download --only-binary=:all:` into `/tmp/theron-obligation-wheels`; their SHA-256 hashes must match. Run `wsl -d kali-linux -- python3 /mnt/d/TheLobe/sem7/theron/scripts/run_obligation_oracles.py`. A mismatch fails rather than silently changing dependencies. Do not execute target modules on the ordinary host. WSL distribution, paths and available namespace support may require local adjustment; an unavailable isolation environment means runtime not run.

`python -m scripts.check_obligation_regressions` requires the previously pinned OWASP/PySASTBench caches and reruns the bounded operational smoke. `python -m scripts.check_obligation_development` uses the older exposed source receipts. Unit/frontend verification: `python -m pytest tests -q`, then `npm test` and `npm run build` in `frontend/`.

## Research acceptance decision

This increment strengthens the implemented system and its reproducibility, but **does not meet the broad research-readiness goal**. Only authorization has a fresh automatic positive; fresh crypto/protocol cases remain missed. There is no independent human label/alert review, no demonstrated cross-layer advantage from MCP correlation, no aggregate production resource guarantee, and no untouched evaluation left among these six source cases. The next detector increment should address recurring parent-object, signed-payload identity and HTTP grammar mechanisms on development data, then freeze before a newly registered external evaluation. Keep adapter-derived evidence separate from independent upstream tests. No paper draft was created.
