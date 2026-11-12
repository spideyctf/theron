"""Evaluate a trusted historical Theron snapshot with the current fixed adapter.

The implementation in --snapshot-root is imported/executed. This must be a trusted
Theron checkout/archive, never the untrusted benchmark application directory.
Benchmark application files remain AST-only inputs to that implementation.
"""
import argparse
from pathlib import Path
import subprocess
import sys


RUNNER = '''
import importlib.util,json,pathlib,sys
snapshot,adapter,dataset,manifest,split,output,revision=sys.argv[1:]
sys.path.insert(0,snapshot)
spec=importlib.util.spec_from_file_location('fixed_evaluation_adapter',adapter)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result=module.evaluate(dataset,json.loads(pathlib.Path(manifest).read_text()),split)
result['scanner_revision']=revision
pathlib.Path(output).write_text(json.dumps(result,indent=2)+'\\n',encoding='utf-8')
print(json.dumps(result['summary'],indent=2))
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot-root',required=True)
    p.add_argument('--revision',required=True)
    p.add_argument('--dataset',required=True)
    p.add_argument('--manifest',required=True)
    p.add_argument('--split',choices=['development','validation','test'],required=True)
    p.add_argument('--output',required=True)
    args=p.parse_args()
    snapshot=Path(args.snapshot_root).resolve()
    if not (snapshot/'scanner/python_analysis.py').is_file() or not (snapshot/'rules').is_dir():
        p.error('Expected a trusted Theron scanner/rules snapshot')
    adapter=Path(__file__).resolve().parents[1]/'scanner/owasp_benchmark.py'
    subprocess.run([sys.executable,'-c',RUNNER,str(snapshot),str(adapter),str(Path(args.dataset).resolve()),
                    str(Path(args.manifest).resolve()),args.split,str(Path(args.output).resolve()),args.revision],
                   cwd=snapshot,check=True)


if __name__=='__main__':
    main()
