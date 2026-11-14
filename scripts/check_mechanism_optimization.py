"""Verify output equivalence after import gating; retain the original timeout."""
from scanner.models import ScanContext,ProjectProfile
from scanner.plugins.sast import SASTScanner
from scanner.rule_loader import RuleLoader
from scanner.finding_utils import normalize_findings
from scripts.evaluate_final_realcode import ROOT,read,write
from scripts.evaluate_obligations import load_sources
from scripts.evaluate_mechanisms import OUT

OPTIMIZATION='ab48e94d3f84ac6a8707a5d71285d05663dae997'


def main():
    prior=read(OUT/'default.json')['records']
    fresh=read(OUT/'vul4py/default.json')['records']
    groups=load_sources()
    checks=[]
    for r in prior+fresh:
        files=groups[r['id'],r['role']] if r in prior else {
            row['path']:(ROOT/'.benchmark-cache/vul4py-pilot'/r['id']/r['role']/row['path']).read_text(encoding='utf-8-sig')
            for row in read(OUT/'vul4py/source-receipts.json')['records'] if row['id']==r['id'] and row.get('role')==r['role']
            and not row.get('expected_absent') and not row.get('error')}
        from scripts.evaluate_vul4py_pilot import application
        files={p:s for p,s in files.items() if application(p)}
        fs=normalize_findings(SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{})))
        actual=[f.to_dict() for f in fs]
        assert actual==r['alerts'],(r['id'],r['role'])
        checks.append(dict(id=r['id'],role=r['role'],alerts_unchanged=True))
    write(OUT/'optimization-equivalence.json',dict(implementation_revision=OPTIMIZATION,
        comparison_revision='6eb6aee2e554c52a5f7519f0f7b6bed016f56f1a',source_exposed=True,records=checks))
    print('Equivalent alert payloads on',len(checks),'case/revision groups',flush=True)
    from scripts import check_library_operations as operations
    operations.OUT=OUT
    operations.CACHE=ROOT/'.benchmark-cache/mechanism-operations'
    operations.IMPLEMENTATION=OPTIMIZATION
    operations.main()


if __name__=='__main__':main()
