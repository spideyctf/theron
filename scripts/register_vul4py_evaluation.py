"""Preregister a project-disjoint pilot from metadata, before source inspection."""
import csv
import hashlib
from scripts.evaluate_final_realcode import ROOT,read,write
from scripts.evaluate_mechanisms import FREEZE,OUT

REVISION='f80f861012cb7b7cfeca7323be51d33e72eaf8f3'
SEED='theron-external-2026-11-14'


def main():
    if (OUT/'vul4py-registration.json').exists():
        raise ValueError('Registration already exists. Preserve exposed membership and create a new dated protocol instead of replacing it.')
    prior=read(ROOT/'docs/evaluation/realworld-2026-11-12/manifest.json')['cases']
    exposed={c['repository'].lower() for c in prior}
    for case in prior:
        identity=case.get('repository_identity',{})
        exposed|={v.lower() for v in [identity.get('canonical'),identity.get('root'),*identity.get('aliases',[])] if isinstance(v,str)}
    exposed|={c['repo'].lower() for c in read(ROOT/'docs/evaluation/obligations-2026-11-14/source-plan.json')['cases']}
    metadata=OUT/'vul4py-metadata.csv'
    rows=list(csv.DictReader(metadata.read_text(encoding='utf-8-sig').splitlines()))
    eligible=[];excluded=[]
    for row in rows:
        repo=row['repo_url'].removeprefix('https://github.com/').removesuffix('.git').strip('/')
        item=dict(row,repository=repo)
        if repo.lower() in exposed:
            excluded.append(dict(item,reason='Repository present in earlier source/evaluation manifest'))
        else:eligible.append(item)
    eligible.sort(key=lambda r:hashlib.sha256((SEED+'\0'+r['vuln_id']).encode()).hexdigest())
    selected=[];projects=set()
    for row in eligible:
        if row['repository'].lower() in projects:continue
        selected.append(row);projects.add(row['repository'].lower())
        if len(selected)==10:break
    assert len(selected)==10
    write(OUT/'vul4py-registration.json',dict(implementation_revision=FREEZE,dataset_repository='tabudz/vul4py',dataset_revision=REVISION,
        metadata_sha256=hashlib.sha256(metadata.read_text(encoding='utf-8-sig').replace('\r\n','\n').encode()).hexdigest(),
        seed=SEED,selection='First ten distinct eligible repositories ordered by SHA256(seed + NUL + vulnerability ID); no mechanism-based selection',
        selected=selected,excluded_prior_projects=excluded,eligible_rows=len(eligible),total_rows=len(rows),
        target_source_opened=False,independent_oracles_verified=False,
        protocol='Freeze before source; retrieve every selected patch/parent and Python source/test receipt. Retain unsupported cases, missing context and oracle/build failures. Never count failed infrastructure as safe. No tuning within this freeze.'))
    print('Registered',len(selected),'project-disjoint candidates from',len(rows),'metadata rows')
    print([(r['vuln_id'],r['repository']) for r in selected])


if __name__=='__main__':main()
