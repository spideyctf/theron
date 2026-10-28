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

- Persistent/stored XSS, template inheritance, context-specific HTML/JS/URL escaping and general database-to-template flows.
- General dynamic dispatch, monkeypatching, reflection, arbitrary decorators and dependency injection, aliasing across multiple mutable instances, and dynamic imports.
- Whole-program control-flow proofs, loop fixed points, general exception reachability and runtime authentication/authorization.
- Third-party package internals, unsupported frameworks, unsupported lockfile formats and actual installed-version resolution from ranges.
- JavaScript/TypeScript remain experimental regex review candidates; they do not have Python-equivalent semantic analysis.
- General exploitability, deployment reachability, independent large-scale false-positive evaluation and held-out real-world CVE validation.

Five call levels, 1500 invocations per entry file and the 500 KB file cap bound analysis. GitHub scans pin an immutable commit for tree/download consistency, and reports expose the SHA. Downloads and advisory lookups use bounded concurrency and timeouts. Scan history is still in memory and the web service is local/single-user.
