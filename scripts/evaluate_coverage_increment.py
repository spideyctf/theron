"""Reproduce the exposed-corpus coverage regression. Target code stays AST-only."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform
import subprocess

from scanner.benchmark import evaluate as tuning_evaluate
from scanner.owasp_benchmark import evaluate
from scanner.realworld_audit import check_freeze
from scripts.probe_realworld_development import probe


FREEZE = '82db6083b37690da0fb77717dd19688474a239dd'
ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def transitions(before, after):
    old = {c['case']: c for c in before['cases']}
    if set(old) != {c['case'] for c in after['cases']}:
        raise ValueError('Case membership changed')
    changes = []
    for case in after['cases']:
        prior = old[case['case']]
        if any(prior[k] != case[k] for k in ['family', 'cwe', 'vulnerable']):
            raise ValueError('Labels or families changed')
        if prior['outcome'] != case['outcome']:
            changes.append(dict(case=case['case'], cwe=case['cwe'], before=prior['outcome'], after=case['outcome']))
    return dict(counts=dict(Counter(f"{c['before']}->{c['after']}" for c in changes)), cases=changes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', default=str(ROOT/'.benchmark-cache/BenchmarkPython'))
    parser.add_argument('--pysastbench', default=str(ROOT/'.benchmark-cache/PySASTBench'))
    parser.add_argument('--real-cache', default=str(ROOT/'.benchmark-cache/realworld-step3'))
    parser.add_argument('--output', default=str(ROOT/'docs/evaluation/coverage-2026-11-13'))
    args = parser.parse_args()
    if subprocess.run(['git', 'diff', '--quiet', FREEZE, '--', 'scanner', 'rules'], cwd=ROOT).returncode:
        raise ValueError('Detector/rules differ from the declared freeze')
    reserve = ROOT/'docs/evaluation/realworld-2026-11-12'
    if not check_freeze(reserve, {n: read(reserve/n) for n in ['inputs.json', 'queries.json', 'github-metadata.json', 'prior-unit-index.json', 'manifest.json']}):
        raise ValueError('Reserve metadata freeze changed')
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    prior_root = ROOT/'docs/evaluation/step5-2026-11-13'
    old_index = read(prior_root/'artifact-hashes.json')
    environment = read(prior_root/'environment.json')
    if canonical_sha(environment) != old_index['artifacts']['environment.json']:
        raise ValueError('Historical implementation provenance changed')
    adapter_path = ROOT/'scanner/owasp_benchmark.py'
    adapter_sha = hashlib.sha256(adapter_path.read_text(encoding='utf-8').encode()).hexdigest()
    if adapter_sha != environment['implementation_normalized_utf8_sha256']['scanner/owasp_benchmark.py']:
        raise ValueError('Scoring adapter changed')
    manifest_path = ROOT/'docs/evaluation/owasp-2026-11-12/split.json'
    manifest = read(manifest_path)
    summary = dict(implementation_revision=FREEZE, python=platform.python_version(),
                   all_owasp_splits_exposed=True, reserved_real_source_opened=False,
                   independent_real_labels=0, split_manifest_sha256=canonical_sha(manifest),
                   comparison='Unchanged labelled-file/CWE adapter; exposed tuning regression, not an independent holdout',
                   splits={})
    for split in ['development', 'validation', 'test']:
        old = read(prior_root/f'{split}-default.json')
        if canonical_sha(old) != old_index['artifacts'][f'{split}-default.json']:
            raise ValueError('Historical result changed')
        current = evaluate(args.dataset, manifest, split)
        if current['dataset_revision'] != old['dataset_revision']:
            raise ValueError('Dataset changed')
        write(out/f'{split}.json', current)
        baselines = {}
        for tool in ['bandit', 'semgrep']:
            name = f'{split}-{tool}.json'
            raw = read(prior_root/name)
            if canonical_sha(raw) != old_index['artifacts'][name]:
                raise ValueError('Historical baseline result changed')
            baselines[tool] = dict(summary=raw['summary'], source=f'../step5-2026-11-13/{name}', canonical_sha256=canonical_sha(raw))
        summary['splits'][split] = dict(before=old['summary'], after=current['summary'],
                                       transitions=transitions(old, current), baselines=baselines, ablations={})
        print(split, json.dumps(current['summary']), flush=True)
        for feature in ['interprocedural', 'local_imports', 'sanitizers']:
            result = evaluate(args.dataset, manifest, split, feature)
            write(out/f'{split}-no-{feature}.json', result)
            summary['splits'][split]['ablations'][feature] = result['summary']
    # Keep error records, including the known unresolved vulnerable function label.
    tuning = tuning_evaluate(args.pysastbench)
    write(out/'pysastbench.json', tuning)
    summary['pysastbench'] = tuning['summary']
    real = probe(read(reserve/'manifest.json'), read(ROOT/'docs/evaluation/development-2026-11-12/selection.json'), args.real_cache)
    write(out/'real-development.json', real)
    if len(real['records']) != 14 or any('error' in r for r in real['records']):
        raise ValueError('Previously exposed development snapshots must remain available and hash-matched')
    summary['real_development_files'] = len(real['records'])
    summary['source_hashes'] = {p: hashlib.sha256((ROOT/p).read_text(encoding='utf-8').encode()).hexdigest()
                                for p in ['scanner/python_analysis.py', 'scanner/owasp_benchmark.py', 'scanner/python_project.py', 'scanner/plugins/sast.py']}
    summary['prior_step5_artifact_index_sha256'] = canonical_sha(old_index)
    summary['target_met'] = all(summary['splits'][s]['after']['recall'] >= .6 for s in ['validation', 'test'])
    write(out/'summary.json', summary)
    write(out/'artifact-hashes.json', {p.name: canonical_sha(read(p)) for p in sorted(out.glob('*.json')) if p.name != 'artifact-hashes.json'})
    print('pysastbench', json.dumps(tuning['summary']), flush=True)
    print('Target met:', summary['target_met'], flush=True)


if __name__ == '__main__':
    main()
