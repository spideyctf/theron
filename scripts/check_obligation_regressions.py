"""Exposed synthetic regression and fixed-snapshot operational smoke."""
from scanner.benchmark import evaluate as tuning_evaluate
from scanner.owasp_benchmark import evaluate as synthetic_evaluate
from scripts.evaluate_final_realcode import ROOT,read,write
from scripts.evaluate_obligations import OUT,FREEZE


def main():
    manifest=read(ROOT/'docs/evaluation/owasp-2026-11-12/split.json')
    summary={}
    for name in ['development','validation','test','pysastbench']:
        result=(tuning_evaluate(ROOT/'.benchmark-cache/PySASTBench') if name=='pysastbench'
                else synthetic_evaluate(ROOT/'.benchmark-cache/BenchmarkPython',manifest,name))
        write(OUT/(name+'.json'),result)
        old=read(ROOT/('docs/evaluation/library-flows-2026-11-14/'+name+'.json'))
        summary[name]=dict(summary=result['summary'],case_outcomes_and_alert_counts_unchanged=result['cases']==old['cases'])
        if name=='pysastbench':summary[name]['fixed_file_alerts']=result['fixed_file_alerts']
        print(name,summary[name],flush=True)
    write(OUT/'synthetic-summary.json',dict(implementation_revision=FREEZE,exposed_tuning_data=True,partitions=summary))
    from scripts import check_library_operations as operations
    operations.OUT=OUT
    operations.CACHE=ROOT/'.benchmark-cache/obligation-operations'
    operations.IMPLEMENTATION=FREEZE
    operations.main()


if __name__=='__main__':main()
