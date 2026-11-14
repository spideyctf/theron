"""Restore only hash-pinned text sources in the obligation evaluation receipts."""
import hashlib
import urllib.request
from scripts.evaluate_final_realcode import ROOT,read,checked_path
from scripts.evaluate_obligations import OUT,CACHE


def main():
    plans={r['id']:r for r in read(OUT/'source-plan.json')['cases']}
    for filename in ['source-receipts.json','runtime-source-receipts.json']:
        for r in read(OUT/filename)['records']:
            if 'error' in r:continue
            if r['revision']!=plans[r['id']]['revisions'][r['role']]:raise ValueError('Revision outside plan')
            path=checked_path(CACHE,'/'.join([r['id'],r['role'],r['path']]))
            if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==r['source_sha256']:continue
            url='https://raw.githubusercontent.com/'+plans[r['id']]['repo']+'/'+r['revision']+'/'+r['path']
            raw=urllib.request.urlopen(url,timeout=30).read(2_000_001)
            if len(raw)>2_000_000 or hashlib.sha256(raw).hexdigest()!=r['source_sha256']:raise ValueError('Pinned source mismatch: '+url)
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    print('All available registered sources restored and verified; original missing-file/transport attempts remain in receipts.')


if __name__=='__main__':main()
