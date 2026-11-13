"""Offline CLI smoke on a pinned Git snapshot; never execute target code."""
import hashlib
from pathlib import Path
import subprocess
import sys
import time

from scanner.utils.helpers import should_scan_file, is_excluded
from scripts.evaluate_final_realcode import ROOT, checked_path, read, write

OUT=ROOT/'docs/evaluation/library-flows-2026-11-14'
CACHE=ROOT/'.benchmark-cache/library-flows-2026-11-14'
IMPLEMENTATION='634573431544a3ef16da99df5fcad35360372971'
TARGET='4c166e0b179e1ff10a3a432e2bd439765b601a81'


def main():
    if subprocess.run(['git','diff','--quiet',IMPLEMENTATION,'--','scanner','rules'],cwd=ROOT).returncode:
        raise ValueError('Declared implementation changed')
    target=CACHE/'fixed-self-target'
    inventory={}
    paths=subprocess.check_output(['git','ls-tree','-r','--name-only',TARGET],cwd=ROOT,text=True).splitlines()
    for name in paths:
        if should_scan_file(name) and not is_excluded(name,[]):
            raw=subprocess.check_output(['git','show',TARGET+':'+name],cwd=ROOT)
            path=checked_path(target,name)
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw)
            inventory[name]=hashlib.sha256(raw).hexdigest()
    write(OUT/'offline-self-inputs.json',dict(target_revision=TARGET,files=inventory))
    report=CACHE/'fixed-self-report.json'
    start=time.perf_counter()
    try:
        run=subprocess.run([sys.executable,'-u','-m','scanner.cli','--local',str(target),'--modules','sast,ai,agentic',
            '--format','json','--output',str(report)],cwd=ROOT,capture_output=True,text=True,timeout=120)
        (CACHE/'fixed-self.log').write_text(run.stdout+'\n'+run.stderr,encoding='utf-8')
        if run.returncode:
            raise RuntimeError('CLI exited '+str(run.returncode))
        result=read(report)
        if set(result['modules_run'])!={'sast','ai','agentic'}:
            raise ValueError('Requested offline modules did not complete')
        compact={k:result[k] for k in ['summary','files_scanned','modules_run']}
        compact['application_findings']=[{k:f.get(k) for k in ['rule_id','file_path','line_number','maturity','evidence_kind','scope']}
                                         for f in result['findings']]
        compact['context_findings']=len(result['context_findings'])
        compact['context_coverage_notices']=[{k:f.get(k) for k in ['rule_id','file_path','description']}
                                            for f in result['context_findings'] if f.get('evidence_kind')=='coverage-notice']
        compact['status']='completed'
    except (subprocess.TimeoutExpired,RuntimeError,ValueError) as exc:
        compact=dict(status='failed',error_type=type(exc).__name__)
    compact.update(implementation_revision=IMPLEMENTATION,target_revision=TARGET,selected_files=len(inventory),
        wall_seconds=time.perf_counter()-start,limit_seconds=120,network_required=False,target_code_executed=False,
        interpretation='One offline CLI smoke with SAST/AI/agentic; SCA/network excluded. Not a throughput ranking or accuracy result.')
    write(OUT/'offline-selfscan.json',compact)
    print(compact,flush=True)
    if compact['status']!='completed':
        raise SystemExit(1)


if __name__=='__main__':
    main()
