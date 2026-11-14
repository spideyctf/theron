# Follow-up: alert precision and paired upstream checks

14 November 2026. Current detector: `7b64719`; preceding precision fix: `8a0a7cb`. Earlier evidence at `f370de1` is retained in this directory. This is exposed development work, not a new holdout evaluation.

## Implementation and regression

- **763 Python tests pass.** The frontend source is unchanged from its last passing 17-test/build checkpoint.
- Imported TLS factories and `getattr` are no longer assumed genuine after local shadowing. Replaced/deleted connection managers invalidate the library contract.
- The new TLS hostname model records native checking at the handshake, manual certificate matching against the same hostname, context/socket aliases and hostname reassignment. Enabling checking after the handshake cannot retroactively validate a socket.
- Factory defaults vary across urllib3 releases. An unknown version produces an INFO coverage notice, not a CWE-labelled vulnerability. Explicitly disabled checking without an observed matching check produces a bounded advisory. Custom/caller-side verification remains an assumption.
- The [current source replay](hostname-followup/development.json) retains **4/10** exposed pilot mechanism candidates and none in repaired mechanism units. Strict CNA matching remains **2/8 labelled cases**; two labels are missing. The original Requests project overlap remains disclosed. The older six-case development set stays at 5/6 mechanisms, with CVAT missed.
- All **1,470** [synthetic outcomes and alert counts remain unchanged](hostname-followup/synthetic/synthetic-summary.json). OWASP exposed test recall remains 73.03%, label precision 100%; PySASTBench recall 78.15%, precision 95.88%.
- The [current operational smoke](hostname-followup/offline-selfscan.json) completes in **52.89 seconds / 120 seconds**, 273 files read from 275 selected. Three application coverage notices, 12 context findings and two oversized inputs remain. This is one bounded workload, not a production-scale performance claim.

## Real-code behavior validation

All ten pilot projects now have a selected behavior pair that distinguishes the vulnerable and repaired revisions, with legitimate-input checks passing on both. The [checked summary](upstream-summary.json), reproduced by `python -m scripts.summarize_upstream_evidence`, separates five unmodified upstream pairs, two adapted upstream pairs and three author-derived pairs. These ten observations are not ten scanner detections. The types of evidence differ:

| Project | Vulnerable behavior check | Repaired check | Functional control on each revision | Evidence type |
| --- | --- | --- | --- | --- |
| html-sanitizer | 1 failure | passes | passes | Earlier unmodified upstream tests |
| MCP SDK | 4 failures | 4 passes | 4 passes | Two selected tests on asyncio/trio; unmodified upstream bodies |
| pymdown | 1 failure | 1 pass | 1 pass | Unmodified upstream path-boundary/file-read tests |
| smolagents | 3 failures | 3 passes | 1 pass | Unmodified upstream indirect-access/assignment tests |
| sigstore-python | 1 failure | 1 pass | 1 pass | Unmodified upstream missing-signed-time/bundle-round-trip tests |
| Requests | 1 failure | 1 pass | 2 passes | Unchanged upstream assertion with an adapted local TLS transport |
| owlmixin | 1 failure | 1 pass | 1 pass | Upstream bodies with historical PyYAML and a command-recording stub |
| urllib3 | wrong hostname accepted | wrong hostname rejected | matching hostname accepted | Author-derived adapter calling the original TLS proxy method |
| SQLparse | unterminated quoted lexer input exceeds 2-second local deadline | completes in about 0.0043 seconds | 427 passes, 3 expected failures | Separate author-derived bounded resource adapter; original patch test passes on both |
| OctoPrint | original helper replaces the transport peer with an untrusted forwarded header | helper retains the transport peer | 17 upstream controls plus two helper controls pass | Author-derived extracted helper adapter; original new-API failures remain API mismatches |

These are selected checks, not complete upstream suites or full Vul4Py acceptance. Runtime verification does not mean Theron detects every reproduced issue: pymdown, owlmixin, sigstore, SQLparse and OctoPrint remain default mechanism misses; urllib3's unknown-version condition remains a coverage notice.

Receipts, source hashes, dependency locks and harness hashes: [Requests](requests-oracle.json), [smolagents](smolagents-oracle.json), [owlmixin](owlmixin-oracle.json), [sigstore](sigstore-oracle.json), [urllib3](urllib3-oracle.json), [OctoPrint](octoprint-oracle.json), [MCP](mcp-oracle.json), [pymdown](pymdown-oracle.json), [SQLparse](sqlparse-oracle.json). Runners are `scripts/run_<project>_oracle.py`; they fail on missing/changed caches rather than substitute current source. No installation hooks are used. Downloaded dependency archives are extracted as data.

Additional paired receipts: [SQLparse resource adapter](sqlparse-resource-oracle.json), running a 41-character unterminated quoted input with a handled 2-second deadline; [OctoPrint identity adapter](octoprint-identity-oracle.json), executing the original helper body with supplied request fields and replacing only its fixed-version deprecation-warning decorator with an identity decorator. These are source-guided author adapters. The SQLparse observation is input/deadline-specific; the OctoPrint observation does not exercise Flask initialization, authentication or reverse-proxy middleware. Their original upstream patch tests remain separately reported.

### Corrections and execution limits

Pytest could prepend a fixed-revision test directory ahead of a root-layout library. Owlmixin's first attempt exposed this problem; it was not a valid security result. Current runners check the target module's import origin and use importlib test loading. All affected selected checks were rerun. Earlier receipts are retained as `*-before-origin-check.json` or `*-attempt1.json`; SQLparse remains nondiscriminating after correction. The historical html-sanitizer runner copied target source and fixed tests into a separate ephemeral package.

Requests uses real TLS over a socketpair, with an ephemeral untrusted certificate and a fixed HTTP response. It does not exercise the original external server. Owlmixin uses PyYAML 3.12, with a disclosed Python 3.13 `collections.Hashable` compatibility alias; its command target is replaced by a recorder. The urllib3 adapter adds a PEP451 importer compatibility method to vendored six; the TLS methods are unchanged. OctoPrint's compatible environment pins netaddr 0.8.0 and uses netifaces2; the initial missing static-version file, later netaddr incompatibility and truncated trace attempts are retained. OctoPrint's original version lookup emits missing-Git-metadata diagnostics but tests proceed.

CVAT's service/database test environment is separate from these ten library projects and remains unverified. Docker Desktop was started, but its backend fails removing the stale `userAnalyticsOtlpHttp.sock` runtime socket and the Linux engine remains unavailable. Automatic approval review rejected the recovery action (stopping the instances started for this work and removing that socket), reporting only `blocked by policy`; no recovery mutation executed. No CVAT containers or service tests ran. This is an operational blocker, not a detection result.

## Individual alerts and OSV

The [action-level review](individual-alert-review.json) covers all **14 original pilot alerts**, with exact source/function/action hashes and linked runtime receipts:

- Four source-supported mechanisms now have runtime corroboration: MCP, html-sanitizer, Requests and smolagents.
- Eight hash occurrences have visible ETag/cache identifier or UI plugin-list fingerprint uses. They are not counted as confirmed vulnerabilities or detections of the reference CVE.
- Two redirect occurrences follow a project-specific validator and fallback assignment. The scanner does not model the helper; guard semantics and deployment configuration remain unresolved.

This is an assistant source assessment supported by external tests, not independent human adjudication or an alert-precision estimate. Historical alerts and labels are unchanged.

The [live OSV calibration](osv-calibration.json) passes **6/6 advisory-specific checks**: Requests 2.31.0/2.32.0 for CVE-2024-35195, html-sanitizer 2.3.0/2.4.2 for CVE-2024-34078 and MCP 1.9.3/1.9.4 for CVE-2025-53366. Repaired references can still match other advisories. Raw responses are retained. The initial MCP calibration mistakenly used already-repaired 1.9.4 as a vulnerable reference; the failed expectation is preserved as `osv-calibration-attempt1.json` rather than counted as a scanner miss. Reference metadata: [OSV MCP advisory](https://osv.dev/vulnerability/CVE-2025-53366).

This calibration uses separate exact-version manifests; it does not add vulnerable packages to Theron or alter the earlier actual-repository OSV result of 134 completed queries, no advisory matches and one unresolved-range notice.

## Research acceptance remains open

Still required: CVAT service validation; original upstream proxy/integration and full suites where claimed; broader SQLparse/OctoPrint application validation beyond the author adapters; better detection of the reproduced misses and custom authorization; fresh project-separated real-code evaluation; independent action-level labels; and measured real-code benefit from combining code/dependency/MCP evidence. Thirteen original correlation controls validate joins, but demonstrate no additional vulnerabilities or improved review decisions. Passing more tests does not close those research gates. No manuscript is created.
