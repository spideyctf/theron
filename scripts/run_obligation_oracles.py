"""Trusted Linux orchestrator: target code executes only in bounded bwrap namespaces.

Run in WSL: python3 /mnt/d/TheLobe/sem7/theron/scripts/run_obligation_oracles.py
Dependency wheels must already exist in /tmp/theron-obligation-wheels.
No build scripts, package installation or target imports run on the host.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import zipfile

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/evaluation/obligations-2026-11-14'
CACHE=ROOT/'.benchmark-cache/obligations'
DEPS=Path(tempfile.mkdtemp(prefix='theron-obligation-deps-'))
wheels={}
for wheel in sorted(Path('/tmp/theron-obligation-wheels').glob('*.whl')):
    wheels[wheel.name]=hashlib.sha256(wheel.read_bytes()).hexdigest()
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            if not (DEPS/info.filename).resolve().is_relative_to(DEPS):raise ValueError('Unsafe wheel path')
        archive.extractall(DEPS)  # Data extraction only; .pth and install scripts are never processed.


def run(source,case,oracle=None,probe=False,python_code=None):
    command=['bwrap','--unshare-all','--die-with-parent','--new-session','--cap-drop','ALL',
        '--ro-bind','/usr','/usr','--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64',
        '--proc','/proc','--dev','/dev','--size','16777216','--tmpfs','/tmp','--dir','/work','--chdir','/work',
        '--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','HOME','/tmp',
        '--setenv','PYTEST_DISABLE_PLUGIN_AUTOLOAD','1',
        '--ro-bind',str(source),'/target','--ro-bind',str(DEPS),'/deps',
        '--ro-bind',str(ROOT/'scripts'),'/harness']
    if oracle:command+=['--ro-bind',str(oracle),'/oracle']
    code=("import os,socket,json; s=socket.socket(); print(json.dumps({'windows_visible':os.path.exists('/mnt/c'),'home_visible':os.path.exists('/home'),'network_result':s.connect_ex(('1.1.1.1',443))}))"
          if probe else "import sys,runpy; sys.dont_write_bytecode=True; sys.path[:0]=['/target','/target/src','/deps']; sys.argv=['oracle',"+repr(case)+"]; runpy.run_path('/harness/obligation_oracle.py',run_name='__main__')")
    if python_code is not None:code=python_code
    command+=['--','/usr/bin/python3','-I','-S','-c',code]
    command=['prlimit','--as=1073741824','--cpu=15','--fsize=1048576','--nproc=64','--',*command]
    start=time.perf_counter()
    with tempfile.TemporaryFile() as output:
        process=subprocess.Popen(command,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
        timed_out=False
        try:process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out=True;os.killpg(process.pid,signal.SIGKILL);process.wait()
        output.seek(0);text=output.read(65536).decode('utf-8','replace')
    return dict(exit_code=process.returncode,timed_out=timed_out,wall_seconds=time.perf_counter()-start,output=text,
                output_truncated=output_length(text)>=65536,command=command)


def output_length(text):return len(text.encode())


def main():
    if not wheels:raise ValueError('No dependency wheels')
    if wheels!=json.loads((OUT/'runtime-dependencies.json').read_text()):raise ValueError('Dependency wheel lock changed')
    for filename in ['source-receipts.json','runtime-source-receipts.json']:
        for r in json.loads((OUT/filename).read_text(encoding='utf-8-sig'))['records']:
            if 'error' in r:continue
            if hashlib.sha256((CACHE/r['id']/r['role']/r['path']).read_bytes()).hexdigest()!=r['source_sha256']:
                raise ValueError('Target source changed')
    probe=run(CACHE/'CVE-2022-24761/fixed','probe',probe=True)
    evidence=json.loads(probe['output'])
    if probe['exit_code'] or evidence['windows_visible'] or evidence['home_visible'] or evidence['network_result']!=101:
        raise ValueError('Isolation probe failed: '+str(probe))
    rows=[]
    for case in ['CVE-2026-82411','CVE-2026-58373','CVE-2024-33663','CVE-2022-39227','CVE-2022-24761','CVE-2024-1135']:
        if case=='CVE-2026-58373':
            rows.append(dict(id=case,status='not_run',reason='Upstream tests require a deployed CVAT service, database and account fixtures; no self-contained oracle registered.'))
            continue
        for role in ['vulnerable','fixed']:
            oracle=CACHE/'CVE-2022-24761/fixed/tests' if case=='CVE-2022-24761' else None
            row=dict(id=case,role=role,oracle_kind='upstream_unmodified' if oracle else 'author_derived_adapter',
                     result=run(CACHE/case/role,case,oracle))
            rows.append(row)
            print(case,role,row['result']['exit_code'],row['result']['output'][-700:],flush=True)
    result=dict(isolation='Unprivileged WSL bubblewrap namespaces; not a VM or deployed application test',
        probe=probe,python_version=subprocess.check_output(['python3','--version'],text=True).strip(),
        limits=dict(wall_seconds=30,cpu_seconds_per_process=15,address_space_bytes_per_process=1073741824,process_limit=64,
                    tmpfs_bytes=16777216,output_file_bytes=1048576,returned_output_bytes=65536),
        harness_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),ROOT/'scripts/obligation_oracle.py']},
        dependency_wheels=wheels,records=rows,
        interpretation='Nonzero execution/collection errors and absent oracles are inconclusive, never safe/clean results. Author-derived adapters do not establish whole-application exploitability.')
    (OUT/'runtime.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
