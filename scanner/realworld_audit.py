"""Metadata-only preparation for a real-world study. Never executes target code.

Snippet contents are used only for exact hashes, never emitted in outputs.
Network evidence is supplied as a separately filtered GitHub metadata cache.
"""
import argparse
import ast
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import textwrap
from urllib.parse import urlsplit


POLICY = 'theron-realworld-metadata-v1'
SEED = 'theron-realworld-2026-11-12-v1'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_digest(value):
    return digest(json.dumps(value, sort_keys=True).encode())


def repository(value):
    url = urlsplit(value)
    if url.scheme != 'https' or url.netloc.lower() != 'github.com' or url.query or url.fragment:
        raise ValueError('Expected a plain HTTPS github.com repository URL')
    parts = url.path.strip('/').split('/')
    if len(parts) != 2:
        raise ValueError('Expected owner/repository')
    owner, name = parts
    name = name.removesuffix('.git')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}', owner) or not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or name in {'.', '..'}:
        raise ValueError('Invalid GitHub repository identity')
    return f'{owner}/{name}'.lower()


def patch_reference(value):
    url = urlsplit(value)
    parts = url.path.strip('/').split('/')
    if len(parts) != 4 or parts[2] != 'commit' or url.query or url.fragment:
        raise ValueError('Expected an unambiguous GitHub commit reference')
    repo = repository(f'{url.scheme}://{url.netloc}/{parts[0]}/{parts[1]}')
    if not re.fullmatch(r'[0-9a-fA-F]{7,40}', parts[3]):
        raise ValueError('Expected hexadecimal revision')
    return repo, parts[3].lower()


def snippet_digest(value):
    if not isinstance(value, str) or not value.strip():
        return None
    value = textwrap.dedent(value.replace('\r\n', '\n').replace('\r', '\n'))
    value = '\n'.join(line.rstrip() for line in value.splitlines()).strip()
    return digest(value.encode())


def prepare_inputs(reserve, raw_bytes, prior_csv_bytes):
    if digest(raw_bytes) != reserve['metadata_sha256']:
        raise ValueError('Reserved raw metadata hash changed')
    rows = json.loads(raw_bytes)
    rows = [r for r in rows if str(r.get('programming_language', '')).lower() == 'python']
    indexed = {r['cve_id']: r for r in rows}
    if len(indexed) != len(rows) or len(rows) != reserve['python_cases']:
        raise ValueError('Python reserve membership changed or contains duplicate CVEs')
    cases = []
    for original in reserve['cases']:
        row = indexed[original['cve_id']]
        if any(row.get(k) != original[k] for k in ['repo', 'patch_url', 'programming_language']):
            raise ValueError('Reserved identity/reference fields changed')
        if any(json_digest(row[role]) != original[role+'_sha256'] for role in ['vul_func', 'fix_func']):
            raise ValueError('Reserved function metadata fields changed')
        cve = row['cve_id']
        blockers, notes = [], []
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
            blockers.append('invalid_cve_identifier')
        try:
            repo = repository(row['repo'])
        except ValueError:
            repo = None
            blockers.append('invalid_repository_reference')
        patches = []
        for value in row['patch_url']:
            try:
                target, revision = patch_reference(value)
                patches.append(dict(repository=target, revision=revision, url=value))
            except ValueError:
                blockers.append('unsupported_patch_reference')
        if not patches:
            blockers.append('no_patch_references')
        locations = []
        for role in ['vul_func', 'fix_func']:
            records = row.get(role, [])
            if not records:
                blockers.append('missing_'+role+'_locations')
            for number, item in enumerate(records):
                path = item.get('file_path')
                revision = item.get('commit', '')
                start, end = item.get('start_line'), item.get('end_line')
                posix = PurePosixPath(path.replace('\\', '/')) if isinstance(path, str) else None
                if not posix or posix.is_absolute() or '..' in posix.parts or not posix.parts or ':' in posix.parts[0] or posix.suffix != '.py':
                    blockers.append('invalid_declared_source_path')
                if not re.fullmatch(r'[0-9a-fA-F]{7,40}', revision):
                    blockers.append('invalid_declared_source_revision')
                if type(start) is not int or type(end) is not int or start < 1 or end < start:
                    blockers.append('invalid_declared_source_span')
                source_hash = snippet_digest(item.get('snippet'))
                if source_hash is None:
                    blockers.append('missing_function_snippet_for_integrity_check')
                locations.append(dict(role=role, location_index=number,
                                      path=posix.as_posix() if posix else None, requested_revision=revision.lower(),
                                      start_line=start, end_line=end, snippet_sha256=source_hash,
                                      localization_count=len(item.get('vul_localization', []))))
        if len(patches) > 1:
            notes.append('multiple_patch_references_require_context_review')
        cases.append(dict(cve_id=cve, repository=repo, patch_references=patches, locations=locations,
                          cwes=sorted(set(re.findall(r'CWE-\d+', json.dumps(row.get('cwe_info', {}))))),
                          input_blockers=sorted(set(blockers)), review_notes=notes))
    prior_rows = list(csv.DictReader(prior_csv_bytes.decode('utf-8-sig').splitlines()))
    prior_projects, invalid_prior_projects, recovered_prior_projects = set(), set(), []
    for row in prior_rows:
        raw_project = row['project'].strip()
        try:
            prior_projects.add(repository(raw_project))
        except ValueError:
            parts = [x for x in re.split(r'(?=https://)', raw_project) if x]
            try:
                recovered = {repository(x) for x in parts}
            except ValueError:
                recovered = set()
            if len(parts) > 1 and recovered:
                prior_projects.update(recovered)
                recovered_prior_projects.append(dict(field_sha256=digest(raw_project.encode()),
                                                      repetitions=len(parts), repositories=sorted(recovered)))
            else:
                invalid_prior_projects.add(raw_project)
    prior_cves = sorted(set(re.findall(r'CVE-\d{4}-\d{4,}', prior_csv_bytes.decode('utf-8-sig'))))
    return dict(policy=POLICY, seed=SEED, metadata_revision=reserve['revision'],
                metadata_sha256=reserve['metadata_sha256'], reserve_sha256=json_digest(reserve),
                prior_csv_sha256=digest(prior_csv_bytes), prior_projects=sorted(prior_projects),
                recovered_prior_project_fields=recovered_prior_projects,
                invalid_prior_projects=sorted(invalid_prior_projects), prior_cves=prior_cves,
                cases=cases)


def queries(inputs):
    projects = set(inputs['prior_projects'])
    revisions = set()
    for case in inputs['cases']:
        if case['repository']:
            projects.add(case['repository'])
            revisions.update((case['repository'], location['requested_revision']) for location in case['locations']
                             if re.fullmatch(r'[0-9a-f]{7,40}', location['requested_revision']))
        for patch in case['patch_references']:
            projects.add(patch['repository'])
            revisions.add((patch['repository'], patch['revision']))
    result = [dict(key='repo:'+repo, kind='repository', repository=repo,
                   url=f'https://api.github.com/repos/{repo}') for repo in sorted(projects)]
    for repo, revision in sorted(revisions):
        url = (f'https://api.github.com/repos/{repo}/git/commits/{revision}' if len(revision) == 40
               else f'https://api.github.com/repos/{repo}/commits?sha={revision}&per_page=1')
        result.append(dict(key=f'commit:{repo}@{revision}', kind='commit', repository=repo,
                           requested_revision=revision, url=url))
    return result


def sanitize_metadata(query, data):
    """Keep only source-free evidence and validate the returned identity/prefix."""
    item = dict(key=query['key'], kind=query['kind'], url=query['url'], status='unresolved')
    if query['kind'] == 'repository':
        if not isinstance(data, dict) or not data.get('full_name'):
            return item | {'reason':'repository_metadata_unavailable'}
        try:
            names = {key: repository('https://github.com/'+value) if value else None for key,value in {
                'full_name':data['full_name'], 'parent_full_name':(data.get('parent') or {}).get('full_name'),
                'source_full_name':(data.get('source') or {}).get('full_name')}.items()}
        except (TypeError, ValueError):
            return item | {'reason':'invalid_repository_metadata_identity'}
        return item | names | dict(status='ok', fork=bool(data.get('fork')), archived=bool(data.get('archived')),
                                   license_spdx=(data.get('license') or {}).get('spdx_id'))
    commit = data[0] if isinstance(data, list) and data else data
    if not isinstance(commit, dict):
        return item | {'reason':'commit_metadata_unavailable'}
    revision = commit.get('sha', '').lower()
    tree = (commit.get('tree') or (commit.get('commit') or {}).get('tree') or {}).get('sha', '')
    parents = [p.get('sha', '') for p in commit.get('parents', [])]
    if (not re.fullmatch('[0-9a-f]{40}', revision) or not revision.startswith(query['requested_revision'])
            or not re.fullmatch('[0-9a-f]{40}', tree) or any(not re.fullmatch('[0-9a-f]{40}', p) for p in parents)):
        return item | {'reason':'revision_prefix_or_git_identity_mismatch'}
    date = ((commit.get('commit') or {}).get('committer') or commit.get('committer') or {}).get('date')
    return item | dict(status='ok', sha=revision, tree_sha=tree, parents=parents, date=date)


def validate_metadata_query(query):
    repo = repository('https://github.com/'+query['repository'])
    if query['kind'] == 'repository':
        expected = f'https://api.github.com/repos/{repo}'
        key = 'repo:'+repo
    elif query['kind'] == 'commit' and re.fullmatch('[0-9a-f]{7,40}', query.get('requested_revision', '')):
        revision = query['requested_revision']
        expected = (f'https://api.github.com/repos/{repo}/git/commits/{revision}' if len(revision)==40
                    else f'https://api.github.com/repos/{repo}/commits?sha={revision}&per_page=1')
        key = f'commit:{repo}@{revision}'
    else:
        raise ValueError('Unsupported metadata query')
    if query['url'] != expected or query['key'] != key:
        raise ValueError('Query URL/key must match the metadata-only endpoint')
    return expected.removeprefix('https://api.github.com/')


def graph_prefix_candidates(query, cache):
    """Candidate expansion from already verified project metadata, never a guessed parent."""
    if query['kind'] != 'commit' or len(query['requested_revision']) == 40:
        return {}
    def root(repo):
        item = cache.get('repo:'+repo,{})
        return item.get('source_full_name') or item.get('parent_full_name') or item.get('full_name') or repo
    project = root(query['repository'])
    candidates = defaultdict(list)
    for key,item in cache.items():
        if item.get('status') != 'ok' or not key.startswith('commit:'):
            continue
        repo = key.removeprefix('commit:').split('@',1)[0]
        if root(repo) != project:
            continue
        for revision in [item.get('sha','')] + item.get('parents',[]):
            if re.fullmatch('[0-9a-f]{40}',revision) and revision.startswith(query['requested_revision']):
                candidates[revision].append(key)
    return {key:sorted(set(value)) for key,value in sorted(candidates.items())}


def prior_snippet_inventory(roots):
    index = defaultdict(set)
    failed = []
    for label, root in roots.items():
        root = Path(root)
        for path in sorted(root.rglob('*.py')):
            content = path.read_text(encoding='utf-8-sig')
            source_id = label+':'+path.relative_to(root).as_posix()
            value = snippet_digest(content)
            if value:
                index[value].add(source_id)
            try:
                tree = ast.parse(content)
            except (SyntaxError, RecursionError):
                failed.append(source_id)
                continue
            lines = content.splitlines()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    starts = {node.lineno}
                    if getattr(node, 'decorator_list', []):
                        starts.add(min(d.lineno for d in node.decorator_list))
                    for start in starts:
                        value = snippet_digest('\n'.join(lines[start-1:node.end_lineno]))
                        if value:
                            index[value].add(source_id+f':{start}-{node.end_lineno}')
    return dict(hashes={k:sorted(v) for k,v in sorted(index.items())}, parse_failures=failed,
                normalization='Line endings, trailing whitespace and common indentation only; whole-file and function/class units')


def build_manifest(inputs, metadata, prior_inventory):
    """Build conservative connected groups and assign them without detector outputs."""
    def identity(repo):
        data = metadata.get('repo:'+str(repo), {})
        if data.get('status') != 'ok':
            return dict(status='unresolved', declared=repo)
        try:
            names = {k:repository('https://github.com/'+data[k]) if data.get(k) else None
                     for k in ['full_name','parent_full_name','source_full_name']}
        except ValueError:
            return dict(status='unresolved', declared=repo)
        if not names['full_name']:
            return dict(status='unresolved', declared=repo)
        return dict(status='ok', declared=repo, canonical=names['full_name'],
                    root=names['source_full_name'] or names['parent_full_name'] or names['full_name'],
                    aliases=sorted({repo} | {v for v in names.values() if v}),
                    license_spdx=data.get('license_spdx'), fork=bool(data.get('fork')))

    def commit(repo, requested):
        record = metadata.get(f'commit:{repo}@{requested}', {})
        full = record.get('sha', '')
        tree = record.get('tree_sha', '')
        parents = record.get('parents', [])
        valid = (record.get('status')=='ok' and re.fullmatch('[0-9a-f]{40}', full)
                 and full.startswith(requested) and re.fullmatch('[0-9a-f]{40}', tree)
                 and isinstance(parents,list) and all(isinstance(p,str) and re.fullmatch('[0-9a-f]{40}',p) for p in parents))
        if not valid:
            return dict(requested_revision=requested, status='unresolved', reason=record.get('reason','metadata_unavailable'))
        return dict(requested_revision=requested, status='resolved', sha=full, tree_sha=tree, parents=parents,
                    evidence_url=record.get('resolved_url',record.get('url')),
                    resolution_strategy=record.get('resolution_strategy','direct_metadata_reference'),
                    graph_evidence_keys=record.get('graph_evidence_keys',[]))

    prior_aliases = set(inputs['prior_projects'])
    unresolved_prior = []
    for repo in inputs['prior_projects']:
        item = identity(repo)
        if item['status']=='ok':
            prior_aliases.update(item['aliases'])
        else:
            unresolved_prior.append(repo)
    cases = []
    for item in inputs['cases']:
        case = json.loads(json.dumps(item))
        ident = identity(case['repository'])
        case['repository_identity'] = ident
        blockers = list(case.pop('input_blockers'))
        notes = set(case['review_notes'])
        overlap = []
        if ident['status']!='ok':
            blockers.append('declared_repository_unresolved')
        else:
            if prior_aliases.intersection(ident['aliases']):
                overlap.append('prior_project_or_fork_root_metadata_exposed')
            if ident['license_spdx'] in {None,'NOASSERTION'}:
                notes.add('repository_license_requires_review')
        if case['cve_id'] in inputs['prior_cves']:
            overlap.append('prior_cve_metadata_exposed')
        for patch in case['patch_references']:
            patch['repository_identity'] = identity(patch['repository'])
            patch['resolution'] = commit(patch['repository'],patch['revision'])
            if patch['resolution']['status']!='resolved':
                blockers.append('patch_commit_unresolved')
            elif len(patch['resolution']['parents']) != 1:
                notes.add('patch_merge_or_root_requires_revision_review')
            target = patch['repository_identity']
            if target['status']!='ok':
                blockers.append('patch_repository_unresolved')
            elif ident['status']=='ok' and target['root'] != ident['root']:
                blockers.append('patch_project_mismatch_requires_review')
        for location in case['locations']:
            location['resolution'] = commit(case['repository'], location['requested_revision'])
            if location['resolution']['status']!='resolved':
                blockers.append('function_snapshot_unresolved')
            matches = prior_inventory['hashes'].get(location['snippet_sha256'], [])
            location['prior_exact_unit_matches'] = matches
            if matches:
                overlap.append('exact_snippet_in_previous_development_corpus')
        vulnerable = {l['resolution']['sha'] for l in case['locations'] if l['role']=='vul_func' and l['resolution']['status']=='resolved'}
        fixed = {l['resolution']['sha'] for l in case['locations'] if l['role']=='fix_func' and l['resolution']['status']=='resolved'}
        if vulnerable.intersection(fixed):
            notes.add('vulnerable_fixed_revision_overlap_requires_review')
        patch_revisions = {p['resolution']['sha'] for p in case['patch_references'] if p['resolution']['status']=='resolved'}
        if fixed - patch_revisions:
            notes.add('fixed_function_revision_outside_patch_references')
        vul_hashes = {l['snippet_sha256'] for l in case['locations'] if l['role']=='vul_func'}
        fix_hashes = {l['snippet_sha256'] for l in case['locations'] if l['role']=='fix_func'}
        if vul_hashes.intersection(fix_hashes)-{None}:
            notes.add('unchanged_snippet_requires_surrounding_context_review')
        case['metadata_blockers'] = sorted(set(blockers))
        case['overlap_reasons'] = sorted(set(overlap))
        case['review_notes'] = sorted(notes)
        case['label_status'] = 'pending_independent_source_and_patch_adjudication'
        case['scorable'] = False
        cases.append(case)

    parents = {c['cve_id']:c['cve_id'] for c in cases}
    def find(key):
        while key != parents[key]:
            key = parents[key]
        return key
    first = {}
    for case in cases:
        ident = case['repository_identity']
        tokens = [('cve',case['cve_id'])]
        tokens.append(('project',ident['root'] if ident['status']=='ok' else case['repository']))
        tokens += [('snippet',l['snippet_sha256']) for l in case['locations'] if l['snippet_sha256']]
        tokens += [('patch',p['repository_identity'].get('root',p['repository']),p['resolution']['sha'])
                   for p in case['patch_references'] if p['resolution']['status']=='resolved']
        for token in tokens:
            previous = first.setdefault(token,case['cve_id'])
            a,b = sorted((find(previous),find(case['cve_id'])))
            parents[b] = a
    components = defaultdict(list)
    for case in cases:
        components[find(case['cve_id'])].append(case)
    groups, candidates = {}, {}
    for members in components.values():
        member_ids = sorted(c['cve_id'] for c in members)
        group_id = 'group-'+json_digest(member_ids)[:20]
        group_blockers = sorted({x for c in members for x in c['metadata_blockers']})
        group_overlap = sorted({x for c in members for x in c['overlap_reasons']})
        partition = 'quarantine' if group_blockers else 'development_only' if group_overlap else None
        groups[group_id] = dict(members=member_ids,metadata_blockers=group_blockers,overlap_reasons=group_overlap,
                               partition=partition,size=len(members))
        if partition is None:
            candidates[group_id] = len(members)
        for case in members:
            case['group_id'] = group_id
    size = sum(candidates.values())
    targets = dict(development=size*.6,validation=size*.2,test=size*.2)
    used = Counter(development=0,validation=0,test=0)
    for group_id in sorted(candidates,key=lambda k:(-candidates[k],digest(f'{SEED}:{k}'.encode()))):
        split = max(targets,key=lambda k:targets[k]-used[k])
        groups[group_id]['partition'] = split
        used[split] += candidates[group_id]
    for case in cases:
        group = groups[case['group_id']]
        case['partition'] = group['partition']
        case['group_blockers'] = group['metadata_blockers']
        case['group_overlap_reasons'] = group['overlap_reasons']
        case['metadata_status'] = ('blocked_pending_metadata_review' if group['metadata_blockers'] else
                                   'development_only_pending_label_review' if group['overlap_reasons'] else
                                   'candidate_pending_label_review')
    cases.sort(key=lambda c:c['cve_id'])
    membership = [{k:c[k] for k in ['cve_id','group_id','partition','metadata_status']} for c in cases]
    return dict(policy=POLICY,seed=SEED,prepared_on='2026-11-12',timezone='Asia/Calcutta',
                status='frozen_metadata_partitions_not_validated_labels', metadata_revision=inputs['metadata_revision'],
                metadata_sha256=inputs['metadata_sha256'], reserve_sha256=inputs['reserve_sha256'],
                prior_csv_sha256=inputs['prior_csv_sha256'], prior_inventory_sha256=json_digest(prior_inventory),
                github_metadata_sha256=json_digest(metadata), membership_sha256=json_digest(membership),
                exposure=dict(metadata_and_hashes_only=True,source_or_patch_bodies_displayed=False,detector_runs=False,
                              images_or_exploits_run=False, previous_realworld_metadata_treated_as_development_exposure=True),
                independence_gates=dict(unresolved_prior_projects=sorted(unresolved_prior),
                                        invalid_prior_project_fields=inputs['invalid_prior_projects'],
                                        prior_unit_parse_failures=prior_inventory['parse_failures'],
                                        semantic_near_duplicates='not_audited',source_and_fix_labels='not_adjudicated'),
                counts=dict(cases=len(cases),declared_repositories=len({c['repository'] for c in cases}),
                            resolved_canonical_repositories=len({c['repository_identity']['canonical'] for c in cases if c['repository_identity']['status']=='ok'}),
                            groups=len(groups),partitions=dict(Counter(c['partition'] for c in cases)),
                            metadata_blockers=dict(Counter(x for c in cases for x in c['metadata_blockers'])),
                            direct_overlap_reasons=dict(Counter(x for c in cases for x in c['overlap_reasons'])),
                            review_flags=dict(Counter(x for c in cases for x in c['review_notes'])),
                            recovered_prior_project_rows=len(inputs['recovered_prior_project_fields']),
                            prior_projects=len(inputs['prior_projects']),scorable_cases=0), groups=groups,cases=cases)


def report(manifest):
    counts = manifest['counts']
    lines = ['# Step 2 metadata audit', '',
             'This is metadata preparation, not a vulnerability-label validation or an accuracy result. No target source/patch bodies were displayed, and no detector or target application was run.', '',
             f"Input: {counts['cases']} Python CVEs; {counts['declared_repositories']} declared repositories; {counts['resolved_canonical_repositories']} resolved canonical repositories; {counts['groups']} connected groups.", '',
             '| Partition | Cases | Groups | Role |', '| --- | ---: | ---: | --- |']
    roles = dict(development='Eligible for subsequent development-source audit', validation='Reserved, labels still pending',
                 test='Reserved final candidates, labels still pending', development_only='Prior exposure/overlap; no independent holdout credit',
                 quarantine='Blocked metadata component; retained for review')
    for split in ['development','validation','test','development_only','quarantine']:
        lines.append(f"| {split} | {counts['partitions'].get(split,0)} | {sum(g['partition']==split for g in manifest['groups'].values())} | {roles[split]} |")
    lines += ['', f"**Scorable cases: {counts['scorable_cases']}.** All labels require source/patch and independent adjudication before scoring. Do not treat fixed snippets as clean negatives.", '',
              '## Metadata blockers', '']
    for reason,number in counts['metadata_blockers'].items():
        lines.append(f'- `{reason}`: {number} directly affected cases; entire connected components are quarantined.')
    if not counts['metadata_blockers']:
        lines.append('No direct metadata blockers were found; semantic label and file-availability checks remain pending.')
    lines += ['', '## Prior exposure and data quality', '']
    for reason,number in counts['direct_overlap_reasons'].items():
        lines.append(f'- `{reason}`: {number} cases directly match; component membership can extend the development-only restriction.')
    lines += [f"- {counts['recovered_prior_project_rows']} older CSV rows contained recoverable concatenated repository URLs. Each recovery is recorded with its field hash; {counts['prior_projects']} prior project identities were considered.",
              '- Project aliases/fork roots and shared patch/snippet identities are grouped conservatively. Exact hashes are not semantic near-duplicate detection.', '',
              '## Pending review flags', '']
    for reason,number in counts['review_flags'].items():
        lines.append(f'- `{reason}`: {number} cases.')
    gates=manifest['independence_gates']
    lines += ['', '## Freeze and remaining gates', '',
              f"Membership SHA-256: `{manifest['membership_sha256']}`.", '',
              f"Unresolved older project identities: {len(gates['unresolved_prior_projects'])}; unrecoverable prior project fields: {len(gates['invalid_prior_project_fields'])}; earlier corpus unit-parse failures: {len(gates['prior_unit_parse_failures'])}.",
              'File existence at the declared revisions, function spans, vulnerability semantics, fix completeness, per-file licensing and semantic near-duplicates remain unverified.',
              'Any later correction must preserve this snapshot and document a versioned amendment; do not silently redraw an exposed holdout.', '',
              'Next step: inspect only the development partition for source/patch label audit. Reserved source remains closed to detector tuning. No detection improvement is claimed by this preparation step.', '']
    return '\n'.join(lines)


def write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')


def frozen_artifacts(artifacts):
    return {name: json_digest(value) for name, value in sorted(artifacts.items())}


def check_freeze(out, artifacts):
    path = Path(out)/'FREEZE.json'
    if not path.is_file():
        return False
    frozen = json.loads(path.read_text())
    if frozen['artifact_canonical_sha256'] != frozen_artifacts(artifacts):
        raise ValueError('Frozen audit differs; preserve this snapshot and use a versioned amendment directory')
    for name, value in artifacts.items():
        if json_digest(json.loads((Path(out)/name).read_text())) != json_digest(value):
            raise ValueError(f'Frozen artifact modified: {name}')
    return True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reserve', required=True)
    p.add_argument('--raw-metadata', required=True)
    p.add_argument('--prior-csv', required=True)
    p.add_argument('--output-dir', required=True)
    p.add_argument('--github-metadata', help='Build the audit from a filtered metadata cache')
    p.add_argument('--freeze', action='store_true', help='Seal canonical artifact hashes after the complete audit')
    p.add_argument('--prior-corpus', action='append', default=[], metavar='LABEL=PATH')
    args = p.parse_args()
    inputs = prepare_inputs(json.loads(Path(args.reserve).read_text()), Path(args.raw_metadata).read_bytes(), Path(args.prior_csv).read_bytes())
    out = Path(args.output_dir)
    queue = queries(inputs)
    artifacts = {'inputs.json':inputs, 'queries.json':queue}
    if args.github_metadata:
        roots = {}
        for value in args.prior_corpus:
            label, separator, path = value.partition('=')
            if not separator or not label or not Path(path).is_dir() or label in roots:
                p.error('--prior-corpus requires unique LABEL=existing-directory entries')
            roots[label] = path
        if not roots:
            p.error('Declare prior corpus roots before checking development overlap')
        inventory = prior_snippet_inventory(roots)
        metadata = json.loads(Path(args.github_metadata).read_text())
        manifest = build_manifest(inputs,metadata,inventory)
        artifacts.update({'github-metadata.json':metadata, 'prior-unit-index.json':inventory, 'manifest.json':manifest})
        if check_freeze(out, artifacts):
            print('Frozen audit matches; no files changed')
            return
        for name, value in artifacts.items():
            write_json(out/name,value)
        (out/'AUDIT.md').write_text(report(manifest),encoding='utf-8')
        if args.freeze:
            write_json(out/'FREEZE.json',dict(policy=POLICY,seed=SEED,prepared_on='2026-11-12',
                       starting_commit='c56c8d59d58abf7a822a6e083837d8a1d3c7add3',
                       membership_sha256=manifest['membership_sha256'],
                       hash_encoding='sha256(json.dumps(value, sort_keys=True).encode()); independent of file newlines',
                       artifact_canonical_sha256=frozen_artifacts(artifacts),
                       source_patch_bodies_opened=False, detector_runs=False, scorable_cases=0))
        print(json.dumps(manifest['counts'],indent=2))
        return
    if args.freeze or (out/'FREEZE.json').exists():
        p.error('A frozen audit requires all metadata and prior corpus inputs; no files changed')
    for name, value in artifacts.items():
        write_json(out/name,value)
    print(json.dumps(dict(cases=len(inputs['cases']), repository_queries=sum(q['kind']=='repository' for q in queue),
                          commit_queries=sum(q['kind']=='commit' for q in queue),
                          input_blockers=dict(Counter(x for c in inputs['cases'] for x in c['input_blockers']))),indent=2))


if __name__=='__main__':
    main()
