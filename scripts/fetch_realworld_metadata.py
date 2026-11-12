"""Fetch only allowlisted public GitHub metadata through an existing gh login.

No blob, contents, patch, diff or full commit-with-files endpoint is allowed.
The cache retains sanitized metadata, never commit messages or source bodies.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess

from scanner.realworld_audit import graph_prefix_candidates, sanitize_metadata, validate_metadata_query, write_json


def fetch(query):
    endpoint=validate_metadata_query(query)
    empty={k:query[k] for k in ['key','kind','url']} | {'status':'unresolved'}
    try:
        result=subprocess.run(['gh','api','--method','GET',endpoint],capture_output=True,text=True,timeout=30)
        if result.returncode:
            return empty | {'reason':'github_cli_request_failed'}
        record=sanitize_metadata(query,json.loads(result.stdout))
        return record | {'transport':'gh-api-metadata'}
    except (subprocess.TimeoutExpired, OSError, ValueError, TypeError, KeyError):
        return empty | {'reason':'github_cli_metadata_unavailable'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--queries',required=True)
    p.add_argument('--cache',required=True)
    p.add_argument('--retry-unresolved',action='store_true')
    p.add_argument('--workers',type=int,choices=range(1,9),default=4)
    p.add_argument('--kind',choices=['repository','commit'])
    args=p.parse_args()
    path=Path(args.cache)
    cache=json.loads(path.read_text()) if path.is_file() else {}
    queue=json.loads(Path(args.queries).read_text())
    for query in queue:
        validate_metadata_query(query)
    queue=[q for q in queue if (not args.kind or q['kind']==args.kind)
           and (q['key'] not in cache or args.retry_unresolved and cache[q['key']]['status']!='ok')]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for index,record in enumerate(pool.map(fetch,queue),1):
            cache[record['key']]=record
            if index%20==0:
                write_json(path,cache)
                print(f'Metadata requests completed: {index}/{len(queue)}',flush=True)
    all_queries=json.loads(Path(args.queries).read_text())
    for query in all_queries:
        if query['kind']!='commit' or cache.get(query['key'],{}).get('status')=='ok':
            continue
        candidates=graph_prefix_candidates(query,cache)
        if len(candidates)!=1:
            continue
        full=next(iter(candidates))
        derived=dict(query, requested_revision=full, key=f"commit:{query['repository']}@{full}",
                     url=f"https://api.github.com/repos/{query['repository']}/git/commits/{full}")
        record=fetch(derived)
        if record['status']=='ok':
            record.update(key=query['key'],url=query['url'],resolved_url=derived['url'],
                          resolution_strategy='unique_prefix_in_verified_project_commit_graph',
                          graph_evidence_keys=candidates[full])
            cache[query['key']]=record
    write_json(path,cache)
    print(json.dumps({'cached':len(cache),'unresolved':sum(x['status']!='ok' for x in cache.values())}))


if __name__=='__main__':
    main()
