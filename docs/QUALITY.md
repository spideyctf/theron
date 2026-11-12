# Detection quality and report interpretation

Theron produces static evidence for review, not automatically confirmed exploits. Passing a benchmark threshold does not establish industry-grade readiness. The current tuning corpus was inspected during development and is not held out.

## Report scopes

Application findings are kept separate from `context_findings` originating in tests, examples and documentation. The frontend provides a Tests / examples tab; JSON and HTML preserve that evidence. SARIF retains it in run properties rather than treating fixture detections as active Code Scanning results. CI thresholds apply to application findings. Agent instruction files such as SKILL.md and AGENTS.md remain application inputs unless they live inside a test/example directory.

This classification is path-based context, not a verdict that a finding is false. Production code can exist in unusual directories and real secrets can exist in tests. Review the context tab before concluding a repository is safe.

Provider-shaped credentials are explicitly unverified, have medium confidence, and carry conditional remediation rather than asserting a live leak. There is no credential-authentication probe. Dependency findings are exact-version advisory matches; they do not prove vulnerable functionality is used. Aliases are grouped transitively per package/version/source, with all identifiers retained. Severity uses authoritative advisory metadata, then scored CVSS vectors, then explicitly provisional medium if neither is available.

## Flow analysis

Python analysis resolves selected imports, framework/CLI inputs, literal assignments, simple constructor/member state, nested/helper returns and repository-local imported functions. It records source/sink paths and lines. Import indexing is AST-only; scanned modules are never imported or executed. Ambiguous module roots and unresolved dynamic calls are not guessed.

HTML escaping, filename normalization and shell quoting apply to their respective contexts. Escaping HTML does not make a value safe for a shell; securing a filename does not make a serialized model safe to deserialize. Unknown sanitizers are not assumed safe. Path operations triggered by web/network input require an observed boundary; a legitimate local CLI file selector is not automatically called directory traversal.

## Why weak fixed examples can still alert

This original, filesystem-free example illustrates why a string prefix is insufficient:

```python
import posixpath
root = "/srv/files"
candidate = posixpath.normpath(root + "/../files-archive/private.txt")
assert candidate.startswith(root)             # passes a weak check
assert posixpath.commonpath([root, candidate]) != root  # outside the root
```

A separator-aware check on normalized paths or component-aware containment is stronger; symlinks, filesystem races and platform differences still need runtime design. Replacing `pickle.load` with `joblib.load` is not a safe deserialization fix. Joblib's [load documentation](https://joblib.readthedocs.io/en/stable/generated/joblib.load.html) explicitly warns about arbitrary code execution.

The benchmark scoring, labels and denominator are unchanged. Fixed-file alerts are retained in both label-matched and whole-file metrics. No fixture names, labels, case IDs or expected outcomes are used by the detector.

## Remaining gaps

The [original OWASP study](evaluation/owasp-2026-11-12/RESULTS.md) preserves its frozen template/category-shift evaluation. The later [coverage repair](evaluation/coverage-2026-11-13/README.md) uses already-exposed outcomes and selected templates to improve coverage: validation/test recall is 91.67%/73.03%. This follow-up is tuning evidence. Labels, scoring and case membership remain unchanged; independent real-world evaluation is still pending.

New resolved API models cover weak hashes, token randomness, request-to-session boundaries, insecure cookie settings, SAX entity configuration, elementpath expressions and LDAP filters. Hash/cookie configuration and session-boundary items carry medium confidence and require contextual review. Storing a request value in a session does not itself prove unauthorized privilege changes. PySASTBench fixed files now carry nine extra weak-hash alerts outside its labelled targets; those alerts have not been independently judged. Quote exclusion protects only substitution inside the matching quoted XPath literal; it does not protect unquoted expressions or other grammars. safe_join protects the modeled path-name boundary only when the base has no observed input taint; package-version flaws, symlinks and filesystem races remain outside that proof.

New flow support includes literal dictionary/list slots, selected append/pop operations, bounded literal conditions, `match`, selected `ConfigParser` values, Flask HTML returns, XPath expressions and redirects. Flask app-factory registration inferred from route syntax and resolved Flask APIs is medium confidence and explicitly disclosed in evidence. Generic `.xpath()` or `.redirect()` methods are not assumed to be library sinks. Host and scheme allowlists are recognized together for selected redirect guards. Arbitrary validators, dynamic collection keys/indexes, complex mutation, aliases and custom escaping implementations remain incomplete. Metadata-only file existence checks are not treated as default file-read vulnerabilities.

- Persistent/stored XSS, template inheritance, context-specific HTML/JS/URL escaping and general database-to-template flows.
- General dynamic dispatch, monkeypatching, reflection, arbitrary decorators and dependency injection, aliasing across multiple mutable instances, and dynamic imports.
- Whole-program control-flow proofs, loop fixed points, general exception reachability and runtime authentication/authorization.
- Third-party package internals, unsupported frameworks, unsupported lockfile formats and actual installed-version resolution from ranges.
- JavaScript/TypeScript remain experimental regex review candidates; they do not have Python-equivalent semantic analysis.
- General exploitability, deployment reachability, independent large-scale false-positive evaluation and held-out real-world CVE validation.

Five call levels, 1500 invocations per entry file and the 500 KB file cap bound analysis. GitHub scans pin an immutable commit for tree/download consistency, and reports expose the SHA. Downloads and advisory lookups use bounded concurrency and timeouts. Scan history is still in memory and the web service is local/single-user.
