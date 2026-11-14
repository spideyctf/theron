"""Same-byte pinned Bandit/Semgrep comparison; target source remains inert."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/evaluation/obligations-2026-11-14'
CACHE=ROOT/'.benchmark-cache/obligation-baselines'
RULE_REV='a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2'


def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')


def stage():
    rules=ROOT/'.benchmark-cache/semgrep-rules'
    if subprocess.check_output(['git','-C',str(rules),'rev-parse','HEAD'],text=True).strip()!=RULE_REV:raise ValueError('Rules revision changed')
    if subprocess.check_output(['git','-C',str(rules),'status','--porcelain','--untracked-files=all','--','python'],text=True).strip():raise ValueError('Dirty rules')
    inventory={}
    for row in read(OUT/'source-receipts.json')['records']:
        if 'error' in row:continue
        path=row['path']
        if path.startswith(('tests/','test/')) or '/tests/' in path:continue
        raw=(ROOT/'.benchmark-cache/obligations'/row['id']/row['role']/path).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=row['source_sha256']:raise ValueError('Source changed')
        name='/'.join([row['id'],row['role'],path])
        dest=CACHE/'sources'/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
        inventory[name]=row['source_sha256']
    rule_files={p.relative_to(rules).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (rules/'python').rglob('*') if p.is_file() and p.suffix in {'.yml','.yaml'}}
    write(OUT/'baseline-inputs.json',dict(source_files=inventory,rule_files=rule_files,rules_revision=RULE_REV))
    with tarfile.open(CACHE/'inputs.tar','w') as archive:
        for name in inventory:archive.add(CACHE/'sources'/name,arcname='sources/'+name,recursive=False)
        for name in rule_files:archive.add(rules/name,arcname='rules/'+name,recursive=False)
    print('Staged',len(inventory),'source files;',len(rule_files),'rules',flush=True)
    python=ROOT/'.benchmark-cache/bandit-venv/Scripts/python.exe'
    version=subprocess.check_output([str(python),'-m','bandit','--version'],text=True)
    if version.splitlines()[0].split()[-1]!='1.9.4':raise ValueError('Bandit version changed')
    result=subprocess.run([str(python),'-m','bandit','-r',str(CACHE/'sources'),'--ignore-nosec','--exit-zero','-f','json','-o',str(CACHE/'bandit.json')],capture_output=True,text=True,timeout=120)
    if result.returncode:raise RuntimeError(result.stderr)


def verify_native():
    inventory=read(OUT/'baseline-inputs.json')
    native=Path(sys.argv[2]) if len(sys.argv)>2 else None
    for name,digest in inventory['source_files'].items():
        if hashlib.sha256(((native or CACHE)/'sources'/name).read_bytes()).hexdigest()!=digest:raise ValueError('Source bytes differ in WSL')
    for name,digest in inventory['rule_files'].items():
        if hashlib.sha256(((native/'rules' if native else ROOT/'.benchmark-cache/semgrep-rules')/name).read_bytes()).hexdigest()!=digest:raise ValueError('Rule bytes differ in WSL')
    write(OUT/'baseline-native-verification.json',dict(source_files=len(inventory['source_files']),rule_files=len(inventory['rule_files']),all_bytes_identical=True,native_stage=str(native)))


def compare():
    native=read(OUT/'baseline-native-verification.json')
    if not native['all_bytes_identical']:raise ValueError('Native verification missing')
    reference=read(OUT/'default.json')['records']
    expected=set(read(OUT/'baseline-inputs.json')['source_files'])
    outputs={}
    for tool in ['bandit','semgrep']:
        raw=read(CACHE/(tool+'.json'))
        if tool=='semgrep' and raw['version']!='1.185.0':raise ValueError('Semgrep version changed')
        covered=({Path(name).relative_to(CACHE/'sources').as_posix() for name in raw['metrics'] if name!='_totals'}
                 if tool=='bandit' else {name.replace('\\','/').split('/sources/',1)[-1] for name in raw['paths']['scanned']})
        if covered!=expected:raise ValueError('Baseline target membership differs: '+tool)
        alerts=[]
        for f in raw.get('results',[]):
            if tool=='bandit':
                path=Path(f['filename']).relative_to(CACHE/'sources').as_posix()
                alerts.append(dict(path=path,line=f['line_number'],rule=f['test_id'],cwe=f.get('issue_cwe',{}).get('id')))
            else:
                path=f['path'].replace('\\','/').split('/sources/',1)[-1]
                alerts.append(dict(path=path,line=f['start']['line'],rule=f['check_id'],cwe=f['extra'].get('metadata',{}).get('cwe',[])))
        units=[]
        for r in reference:
            matches=[a for a in alerts if any(a['path']=='/'.join([r['id'],r['role'],u['path']]) and u['start_line']<=a['line']<=u['end_line'] for u in r['units'])]
            units.append(dict(id=r['id'],role=r['role'],alerts_in_reference_functions=matches))
        outputs[tool]=dict(version='1.9.4' if tool=='bandit' else '1.185.0',covered_files=len(covered),alerts=alerts,units=units,
            errors=raw.get('errors',[]),raw_report_sha256=hashlib.sha256((CACHE/(tool+'.json')).read_bytes()).hexdigest())
    write(OUT/'baselines.json',dict(tools=outputs,native_verification=native,
        flags=dict(bandit=['--ignore-nosec','--exit-zero','all default rules/severities/confidences'],semgrep=['--metrics=off','--disable-version-check','--no-git-ignore','--no-rewrite-rule-ids','--timeout=10','--jobs=2']),
        interpretation='All alerts and errors retained. Function-span overlap is not a semantic vulnerability match. Mixed Windows/WSL execution, no speed ranking.'))
    print({tool:dict(alerts=len(r['alerts']),errors=len(r['errors'])) for tool,r in outputs.items()})


if __name__=='__main__':{'stage':stage,'verify-native':verify_native,'compare':compare}[sys.argv[1]]()
