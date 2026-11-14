"""Already-exposed library sources: development observations, never a fresh holdout."""
from collections import defaultdict
import hashlib
from scanner.models import ScanContext,ProjectProfile
from scanner.plugins.sast import SASTScanner
from scanner.rule_loader import RuleLoader
from scanner.finding_utils import normalize_findings
from scripts.evaluate_final_realcode import ROOT,read,write,snapshot_key
from scripts.evaluate_obligations import OUT,FREEZE


def main():
    rows=read(ROOT/'docs/evaluation/final-validation-2026-11-13/source-exposure.json')['records']
    groups=defaultdict(dict)
    for r in rows:
        raw=(ROOT/'.benchmark-cache/final-realcode/stage'/snapshot_key(r)).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=r['source_sha256']:raise ValueError('Original source bytes changed')
        groups[r['cve_id'],r['role'],r['revision']][r['path']]=raw.decode('utf-8-sig')
    entries=read(ROOT/'docs/evaluation/library-flows-2026-11-14/entrypoint-models.json')['analysis_entrypoints']
    results={}
    for mode in ['default','configured']:
        records=[]
        for (cve,role,revision),files in groups.items():
            config=dict(analysis_entrypoints=[] if mode=='default' else [e for e in entries if e['file'] in files])
            fs=normalize_findings(SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),config)))
            records.append(dict(cve_id=cve,role=role,revision=revision,alerts=[f.to_dict() for f in fs]))
        results[mode]=records
    write(OUT/'exposed-development.json',dict(implementation_revision=FREEZE,source_guided_development=True,new_holdout=False,
        modes=results,interpretation='Already-exposed source replay. New obligation candidates are not retroactive corrections to the original 0/9 frozen result.'))
    for mode,records in results.items():
        print(mode,[(r['cve_id'],r['role'],[(f['rule_id'],f['file_path'],f['line_number']) for f in r['alerts']]) for r in records if r['alerts']],flush=True)


if __name__=='__main__':main()
