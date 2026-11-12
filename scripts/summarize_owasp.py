"""Summarize committed evaluation outcomes; stdlib only, no corpus execution."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import random


def cluster_intervals(cases, samples=2000):
    groups = defaultdict(Counter)
    for case in cases:
        groups[case['family']][case['outcome']] += 1
    families = sorted(groups)
    rng = random.Random(20261112)
    distributions = defaultdict(list)
    for _ in range(samples):
        counts = sum((groups[rng.choice(families)] for _ in families), Counter())
        tp, fp, fn = (counts[k] for k in ['tp', 'fp', 'fn'])
        for name, numerator, denominator in [('precision', tp, tp+fp), ('recall', tp, tp+fn), ('f1', 2*tp, 2*tp+fp+fn)]:
            if denominator:
                distributions[name].append(numerator/denominator)
    result = {}
    for metric in ['precision', 'recall', 'f1']:
        values = sorted(distributions[metric])
        result[metric] = dict(lower=values[int(.025*(len(values)-1))] if values else None,
                              upper=values[int(.975*(len(values)-1))] if values else None,
                              undefined_resamples=samples-len(values))
    return dict(method='Percentile bootstrap of upstream template-family clusters', seed=20261112,
                resamples=samples, clusters=len(families), level=.95,
                note='Few template groups and shared helpers limit independence; intervals are descriptive, not real-world confidence guarantees.',
                intervals=result)


def pct(value):
    return 'undefined' if value is None else f'{value*100:.2f}%'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory', default='docs/evaluation/owasp-2026-11-12')
    args = p.parse_args()
    root = Path(args.directory)
    manifest = json.loads((root/'split.json').read_text())
    summary = {'dataset_revision':manifest['revision'], 'protocol':manifest['protocol'],
               'split_sha256':hashlib.sha256((root/'split.json').read_bytes()).hexdigest(), 'results':{}}
    lines = ['# Frozen OWASP evaluation results', '',
             'Default Python SAST, all labelled categories. These are synthetic file/CWE case metrics, not alert-level exploit precision or the official OWASP scorecard.', '',
             'Detector freeze: `a504494e35b961770a5c37896a7f115bfe025088`. No detector changes followed validation/test unblinding. The later adapter change adds Semgrep JSON import only.', '',
             '| Split | Engine | TP | FN | FP | TN | Errors | Precision | Recall | F1 |',
             '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for split in ['development', 'validation', 'test']:
        for label in ['before', 'after', 'bandit', 'semgrep']:
            path = root/f'{split}-{label}.json'
            if not path.exists():
                continue
            raw = json.loads(path.read_text())
            s = raw['summary']
            name = f'{split}-{label}'
            summary['results'][name] = {'summary':s, 'artifact_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                                        'cluster_bootstrap':cluster_intervals(raw['cases'])}
            title = 'Theron before' if label == 'before' else 'Theron frozen' if label == 'after' else label.title()
            lines.append(f"| {split} | {title} | {s['tp']} | {s['fn']} | {s['fp']} | {s['tn']} | {s['errors']} | {pct(s['precision'])} | {pct(s['recall'])} | {pct(s['f1'])} |")
    lines += ['', '## Ablations', '',
              '| Split | Disabled feature | TP | FN | FP | TN | Precision | Recall |',
              '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for split in ['development', 'validation', 'test']:
        for feature in ['interprocedural', 'local_imports', 'sanitizers']:
            path = root/f'{split}-without-{feature}.json'
            raw = json.loads(path.read_text())
            s = raw['summary']
            summary['results'][f'{split}-without-{feature}'] = {'summary':s, 'artifact_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
            lines.append(f"| {split} | {feature} | {s['tp']} | {s['fn']} | {s['fp']} | {s['tn']} | {pct(s['precision'])} | {pct(s['recall'])} |")
    lines += ['', '## Interpretation', '',
              '- Test detection increased from 3 to 14 of 89 vulnerable cases, with five fixed-case matches both before and after. The test split has only six coarse families.',
              '- Validation recall is zero: its category mix exposes unsupported and unmodelled behavior. This result must remain visible.',
              '- Both pinned baselines detect more labelled vulnerabilities on validation/test. Theron has fewer fixed-case matches on test; neither number alone establishes superiority.',
              '- Disabling interprocedural/local-import analysis loses two development detections. Disabling context-specific sanitizer flags adds eight development false-positive cases. All three ablations are neutral on validation/test, so the held-out gains cannot be attributed to them.',
              '- The baseline versions, configurations, semantic CWE mappings and unmatched-alert behavior are documented in README.md. Per-CWE and per-case outcomes remain in each raw result.',
              '- The initial baseline is reconstructed from archived commit 34f6ab0, not a guessed reproduction of its behavior. The before/after detector source hashes are recorded.',
              '- Bootstrap intervals and undefined resample counts are in summary.json. With few related templates they do not establish real-world generalization or statistical superiority.',
              '- Validation/test outcomes are now exposed. Keep them as a frozen report/regression resource; future tuning based on these outcomes needs a new untouched final evaluation.',
              '- Runtime numbers are single-run diagnostics across different tool environments; do not present them as a fair performance ranking.', '']
    (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    (root/'RESULTS.md').write_text('\n'.join(lines),encoding='utf-8')
    print('\n'.join(lines[:22]))


if __name__=='__main__':
    main()
