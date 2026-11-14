"""Live advisory-specific calibration, separate from the actual repository scan."""
import hashlib
import json
from pathlib import Path
from datetime import datetime,timezone

from scanner.models import ScanContext,ProjectProfile
from scanner.plugins.sca import SCAScanner
from scanner.rule_loader import RuleLoader

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/evaluation/evidence-2026-11-14'
PAIRS=[('requests','2.31.0','2.32.0','CVE-2024-35195'),
       ('html-sanitizer','2.3.0','2.4.2','CVE-2024-34078'),
       ('mcp','1.9.3','1.9.4','CVE-2025-53366')]


def main():
    rows=[];responses=[]
    for package,before,after,cve in PAIRS:
        for role,version in [('vulnerable_reference',before),('repaired_reference',after)]:
            scanner=SCAScanner();manifest=f'{package}=={version}\n'
            findings=scanner.scan(ScanContext({'requirements.txt':manifest},{},ProjectProfile(),RuleLoader(),{}))
            key=f'PyPI:{package}@{version}'
            complete=key in scanner._osv_cache
            aliases={identity for advisory in scanner._osv_cache.get(key,[]) for identity in [advisory['id'],*advisory.get('aliases',[])]}
            matched=cve in aliases
            rows.append(dict(package=package,version=version,role=role,reference_advisory=cve,
                complete_lookup=complete,reference_advisory_matched=matched,
                expected_reference_advisory_match=role=='vulnerable_reference',
                agrees_with_reference=complete and matched==(role=='vulnerable_reference'),
                manifest_sha256=hashlib.sha256(manifest.encode()).hexdigest(),
                findings=[f.to_dict() for f in findings]))
            responses.append(dict(query=key,complete=complete,advisories=scanner._osv_cache.get(key)))
    result=dict(queried_at=datetime.now(timezone.utc).isoformat(),reference_pairs=PAIRS,records=rows,
        exact_checks_passed=sum(r['agrees_with_reference'] for r in rows),total=len(rows),
        implementation_file_sha256={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ['scanner/plugins/sca.py','scanner/advisories.py']},
        reference_sources=['https://osv.dev/vulnerability/CVE-2024-35195','https://osv.dev/vulnerability/CVE-2024-34078','https://osv.dev/vulnerability/CVE-2025-53366'],
        interpretation='Live positive/repair advisory-specific calibration on synthetic exact manifests. These packages were not added to Theron. A repaired reference can match other advisories; no installed/reachable vulnerability or safe upgrade is inferred. This is development calibration, not independent vulnerability-discovery accuracy. The initial attempt incorrectly used already-repaired MCP 1.9.4 as a vulnerable reference; its failed expectation and responses are retained as attempt1, not counted as a scanner miss.')
    for name,value in [('osv-calibration.json',result),('osv-calibration-responses.json',dict(records=responses))]:
        (OUT/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    print([(r['package'],r['version'],r['reference_advisory_matched'],r['agrees_with_reference']) for r in rows],flush=True)
    if not all(r['agrees_with_reference'] for r in rows):raise SystemExit(1)


if __name__=='__main__':main()
