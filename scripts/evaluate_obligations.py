"""Replay the preregistered, frozen obligation increment without importing targets."""
import ast
import hashlib
import subprocess
from collections import defaultdict

from scanner.models import ScanContext, ProjectProfile
from scanner.plugins.sast import SASTScanner
from scanner.rule_loader import RuleLoader
from scanner.finding_utils import normalize_findings
from scripts.evaluate_final_realcode import ROOT, read, write

FREEZE='8c10fdbc904ef9323d00134878f5b2c6ed0097d0'
OUT=ROOT/'docs/evaluation/obligations-2026-11-14'
CACHE=ROOT/'.benchmark-cache/obligations'
UNITS={
 'CVE-2026-82411':{'src/objects/api/v2/views.py':{'ObjectViewSet.history_detail'}},
 'CVE-2026-58373':{'cvat/apps/quality_control/views.py':{'QualityReportViewSet.get_queryset'}},
 'CVE-2024-33663':{'jose/backends/native.py':{'HMACKey.__init__'},'jose/backends/cryptography_backend.py':{'CryptographyHMACKey.__init__'}},
 'CVE-2022-39227':{'python_jwt/__init__.py':{'verify_jwt'}},
 'CVE-2022-24761':{'src/waitress/receiver.py':{'ChunkedReceiver.received'},'src/waitress/parser.py':{'HTTPRequestParser.parse_header'}},
 'CVE-2024-1135':{'gunicorn/http/message.py':{'Message.parse_headers','Message.set_body_reader','Request.set_body_reader'}},
}


def functions(nodes,prefix=''):
    for node in nodes:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
            name=prefix+node.name
            if not isinstance(node,ast.ClassDef):yield name,node
            yield from functions(node.body,name+'.')


def load_sources():
    groups=defaultdict(dict)
    for r in read(OUT/'source-receipts.json')['records']:
        if 'error' in r:continue
        path=CACHE/r['id']/r['role']/r['path']
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=r['source_sha256']:raise ValueError('Source receipt changed: '+str(path))
        groups[r['id'],r['role']][r['path']]=raw.decode('utf-8-sig')
    return groups


def evaluate(out=OUT,freeze=FREEZE,source_guided=False):
    if subprocess.run(['git','diff','--quiet',freeze,'--','scanner','rules'],cwd=ROOT).returncode:
        raise ValueError('Frozen scanner changed; preserve this run before a separately labelled development increment')
    groups=load_sources()
    cna_cwes={r['id']:sorted({d['cweId'] for t in r['record']['containers']['cna'].get('problemTypes',[])
                for d in t.get('descriptions',[]) if d.get('cweId')}) for r in read(OUT/'external-cve-records.json')}
    modes={'default':[], 'no-auth':['auth_obligations'],'no-crypto':['crypto_obligations'],'no-protocol':['protocol_obligations']}
    summaries={}
    for mode,disabled in modes.items():
        records=[]
        for (cve,role),files in groups.items():
            # Tests are oracle/context receipts, never mixed into application alert burden.
            sources={p:s for p,s in files.items() if not (p.startswith(('test/','tests/')) or '/tests/' in p)}
            fs=normalize_findings(SASTScanner().scan(ScanContext(sources,{},ProjectProfile(),RuleLoader(),dict(analysis_disabled_features=disabled))))
            units=[]
            for path,names in UNITS[cve].items():
                code=sources[path];lines=code.splitlines()
                found=set()
                for name,node in functions(ast.parse(code).body):
                    if name in names:
                        found.add(name)
                        units.append(dict(path=path,function=name,start_line=node.lineno,end_line=node.end_lineno,
                            snippet_sha256=hashlib.sha256('\n'.join(lines[node.lineno-1:node.end_lineno]).encode()).hexdigest()))
                if found!=names:raise ValueError('Missing registered mechanism function: '+str(names-found))
            alerts=[f.to_dict() for f in fs]
            matches=[f for f in alerts if f['severity']!='INFO' and f['rule_id'].startswith('PY-OBL-')
                     and any(u['path']==f['file_path'] and u['start_line']<=f['line_number']<=u['end_line'] for u in units)]
            records.append(dict(id=cve,role=role,files=len(sources),units=units,alerts=alerts,semantic_unit_candidates=matches,
                cna_cwes=cna_cwes[cve],strict_cna_cwe_scorable=bool(cna_cwes[cve]),
                strict_cna_cwe_unit_matches=[f for f in alerts if f['severity']!='INFO' and f['cwe'] in cna_cwes[cve]
                    and any(u['path']==f['file_path'] and u['start_line']<=f['line_number']<=u['end_line'] for u in units)],
                scanner_errors=[f for f in alerts if f['rule_id']=='PY-PARSE-001']))
        summary=dict(vulnerable_cases_with_obligation_candidates=sorted({r['id'] for r in records if r['role']=='vulnerable' and r['semantic_unit_candidates']}),
                     patched_cases_with_obligation_candidates=sorted({r['id'] for r in records if r['role']=='fixed' and r['semantic_unit_candidates']}),
                     application_alerts=sum(len(r['alerts']) for r in records),scanner_errors=sum(len(r['scanner_errors']) for r in records),
                     strict_cna_cwe_vulnerable_match_cases=sorted({r['id'] for r in records if r['role']=='vulnerable' and r['strict_cna_cwe_unit_matches']}),
                     strict_cna_cwe_patched_match_cases=sorted({r['id'] for r in records if r['role']=='fixed' and r['strict_cna_cwe_unit_matches']}),
                     strict_cna_cwe_unscorable_cases=sorted({r['id'] for r in records if not r['strict_cna_cwe_scorable']}))
        write(out/(mode+'.json'),dict(implementation_revision=freeze,records=records,summary=summary,
            source_guided_development=source_guided,
            labels='Upstream advisory/repair roles plus author-derived function units; no independent human adjudication',
            interpretation=('Already exposed development source; no new held-out accuracy. ' if source_guided else 'Fresh source exposure after scanner freeze; purposive metadata-aware selection. ')
                +'Not real-world accuracy or deployed exploitability. Patched files are not globally clean.'))
        summaries[mode]=summary
        print(mode,summary,flush=True)
    write(out/'static-summary.json',dict(implementation_revision=freeze,candidates=6,source_guided_development=source_guided,modes=summaries))


if __name__=='__main__':evaluate()
