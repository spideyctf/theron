"""Exposed-corpus regression replay after the operational crash fix, not a holdout."""
import hashlib
import json
import subprocess

from scanner.benchmark import evaluate as tuning_evaluate
from scanner.owasp_benchmark import evaluate as synthetic_evaluate
from scripts.evaluate_final_realcode import ROOT, OUT, read, write

REPAIR='cfbfb83db97e468035a23c7ad19c0597bb46c317'


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


def main():
    if subprocess.run(['git','diff','--quiet',REPAIR,'--','scanner','rules'],cwd=ROOT).returncode:
        raise ValueError('Declared operational repair changed')
    previous=ROOT/'docs/evaluation/flow-completion-2026-11-13'
    manifest=read(ROOT/'docs/evaluation/owasp-2026-11-12/split.json')
    rows=[]
    for name in ['development','validation','test','pysastbench']:
        old=read(previous/(name+'.json'))
        current=(tuning_evaluate(ROOT/'.benchmark-cache/PySASTBench') if name=='pysastbench'
                 else synthetic_evaluate(ROOT/'.benchmark-cache/BenchmarkPython',manifest,name))
        row=dict(dataset=name,summary=current['summary'],case_count=len(current['cases']),
            all_case_outcomes_and_alert_counts_identical=current['cases']==old['cases'],
            previous_cases_canonical_sha256=digest(old['cases']),current_cases_canonical_sha256=digest(current['cases']),
            summaries_identical=current['summary']==old['summary'])
        if name=='pysastbench':
            row['fixed_file_alerts']=current['fixed_file_alerts']
        rows.append(row)
        print(name,row['summary'],'same cases:',row['all_case_outcomes_and_alert_counts_identical'],flush=True)
    write(OUT/'post-repair-regressions.json',dict(implementation_revision=REPAIR,
        exposed_corpora=True,new_heldout_accuracy=False,previous_results='docs/evaluation/flow-completion-2026-11-13',records=rows))
    if not all(r['all_case_outcomes_and_alert_counts_identical'] and r['summaries_identical'] for r in rows):
        raise ValueError('Operational repair changed exposed-corpus outcomes; inspect recorded deltas')


if __name__=='__main__':
    main()
