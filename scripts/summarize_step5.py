"""Summarize frozen regression/development evidence, without inventing real-code labels."""
import argparse
import json
from pathlib import Path
from urllib.parse import quote

from scripts.evaluate_step5 import FREEZE, REPO, SPLITS, FEATURES, check_implementation, read, write, sha
from scripts.summarize_owasp import cluster_intervals


def draft_match(alerts,path,cwes,line):
    if line is None:
        return None
    if type(line) is not int or line<=0:
        raise ValueError('Draft target line must be a positive integer or unassigned')
    return any(a.get('path')==path and a.get('line_number')==line
               and a.get('evidence_kind')!='coverage-notice'
               and set(cwes).intersection(a.get('cwes',[a.get('cwe')])) for a in alerts)


def theron_alerts(record,mode):
    path='/'.join([record['cve_id'],record['role'],record['path']])
    return [dict(f,path=path) for f in record['modes'][mode]]


def real_summary(root):
    review={c['cve_id']:c for c in read(REPO/'docs/evaluation/development-2026-11-12/review.json')['cases']}
    upstream={c['cve_id']:c for c in read(REPO/'docs/evaluation/realworld-2026-11-12/manifest.json')['cases']}
    sources=read(root/'real-theron.json')['records']
    baselines={tool:read(root/('real-'+tool+'.json')) for tool in ['bandit','semgrep']}
    rows=[]
    for record in sources:
        cve,role=record['cve_id'],record['role']
        path='/'.join([cve,role,record['path']])
        line=review[cve]['target_sink_lines'].get(role)
        cwes=upstream[cve]['cwes']
        row=dict(cve_id=cve,role=role,path=record['path'],proposed_sink_line=line,upstream_cwes=cwes,
                 independent_label_status='pending',outcomes={})
        for mode in ['default','experimental']:
            alerts=theron_alerts(record,mode)
            row['outcomes']['theron_'+mode]=dict(target_candidate=draft_match(alerts,path,cwes,line),
                alerts=sum(a['evidence_kind']!='coverage-notice' for a in alerts),
                notices=sum(a['evidence_kind']=='coverage-notice' for a in alerts))
        for tool,data in baselines.items():
            errors=[e for e in data['errors'] if e['path']==path or (e['path'] is None and e['level']=='error')]
            row['outcomes'][tool]=dict(target_candidate=None if errors else draft_match(data['alerts'],path,cwes,line),
                alerts=sum(a['path']==path for a in data['alerts']),errors=len(errors))
        rows.append(row)
    variants=read(root/'real-ablations.json')['variants']
    ablations={}
    for feature,records in variants.items():
        ablations[feature]={}
        for mode in ['default','experimental']:
            totals={role:0 for role in ['vul_func','fix_func']}
            for r in records:
                line=review[r['cve_id']]['target_sink_lines'].get(r['role'])
                if line is not None:
                    totals[r['role']]+=bool(draft_match(theron_alerts(r,mode),'/'.join([r['cve_id'],r['role'],r['path']]),upstream[r['cve_id']]['cwes'],line))
            ablations[feature][mode]=totals
    return dict(independent_labels=False,scorable_cases=0,records=rows,ablations=ablations,
                limitation='Strict CWE + previously proposed sink line; three pairs lack matching context. All seven pairs remain listed, and no validated accuracy denominator exists.')


def review_packet(root):
    manifest={c['cve_id']:c for c in read(REPO/'docs/evaluation/realworld-2026-11-12/manifest.json')['cases']}
    records=read(root/'real-theron.json')['records']
    packet,key=[],[]
    for r in records:
        case=manifest[r['cve_id']]
        locations=[l for l in case['locations'] if l['role']==r['role'] and l['path']==r['path']]
        revision=locations[0]['resolution']['sha']
        subject='R-'+sha((r['cve_id']+'/'+r['role']+'/'+r['path']).encode())[:10]
        packet.append(dict(subject=subject,source_url='https://github.com/'+case['repository']+'/blob/'+revision+'/'+quote(r['path'],safe='/'),
            declared_function_spans=[dict(start_line=l['start_line'],end_line=l['end_line'],snippet_sha256=l['snippet_sha256']) for l in locations],
            review_status='pending',reviewer=None,review_date=None,judgement=None,cwe=None,
            untrusted_source=None,dangerous_sink=None,guard_assessment=None,required_context=None,
            proposed_matching_unit=None,rationale=None,reviewer_relationship_to_detector_development=None,
            tool_outputs_or_patch_labels_seen=None))
        key.append(dict(subject=subject,cve_id=r['cve_id'],upstream_role=r['role'],path=r['path']))
    write(root/'independent-review-packet.json',dict(status='Awaiting independent human review',
        blinding='Tool outputs and assistant judgements omitted; not a double-blind study',
        instructions=['Review source statically; do not run target setup/scripts/exploits.',
                      'Record dangerous, safe_for_specific_flow, or unknown. Missing caller/guard context requires unknown, not an invented label.',
                      'Identify source, sink, CWE and matching unit with evidence before consulting the key or tool reports.',
                      'Upstream patches and role labels do not automatically establish a clean negative.'],subjects=sorted(packet,key=lambda r:r['subject'])))
    write(root/'review-key.json',dict(instructions='Keep separate until initial independent annotations are recorded; upstream roles are not independently validated verdicts.',subjects=key))
    lines=['# Independent static review worksheet','',
           'Give this worksheet and independent-review-packet.json to a reviewer who did not tune the detector. Keep the key and tool results separate until initial annotations are recorded. This omits tool outputs; it is not a double-blind study.','',
           'Read source statically. Do not run setup scripts, applications or exploits. Use dangerous, safe_for_specific_flow, or unknown. Identify source, sink, CWE and guard evidence; missing caller/context requires unknown. Patched versions are not automatically safe. Disclose your relationship to detector development and any outputs/patch labels already seen.','',
           '| Subject | Source snapshot | Declared focus spans | Judgement | CWE / source / sink / guards | Reviewer / date |',
           '| --- | --- | --- | --- | --- | --- |']
    for row in sorted(packet,key=lambda r:r['subject']):
        spans=', '.join(f"{s['start_line']}-{s['end_line']}" for s in row['declared_function_spans'])
        lines.append(f"| {row['subject']} | [Immutable source]({row['source_url']}) | {spans} | pending | pending | pending |")
    lines += ['', 'Record rationale, required context, exact matching unit and disclosure fields in the JSON packet. Store completed annotations as a new review artifact; preserve the pending template and do not silently rewrite denominators.','']
    (root/'INDEPENDENT-REVIEW.md').write_text('\n'.join(lines),encoding='utf-8')


def summarize(root):
    synthetic={}
    historical={}
    for split in SPLITS:
        synthetic[split]={}
        historical[split]={}
        for tool,label in [('theron','default'),('bandit','bandit'),('semgrep','semgrep')]:
            data=read(root/(split+'-'+label+'.json'))
            synthetic[split][tool]=dict(summary=data['summary'],total_alerts=data['total_alerts'],
                notices=len(data['coverage_notices']),cluster_intervals=cluster_intervals(data['cases']))
            old=read(REPO/'docs/evaluation/owasp-2026-11-12'/(split+'-'+('after' if tool=='theron' else tool)+'.json'))
            previous={r['case']:r['outcome'] for r in old['cases']}
            current={r['case']:r['outcome'] for r in data['cases']}
            changes=[dict(case=case,previous=previous[case],current=current[case]) for case in previous if previous[case]!=current[case]]
            historical[split][tool]=dict(case_outcomes_unchanged=not changes,changed_cases=changes,
                                         previous_summary=old['summary'],current_summary=data['summary'])
    ablations={split:{feature:read(root/(split+'-'+feature+'.json'))['summary'] for feature in FEATURES[1:]} for split in SPLITS}
    control=read(root/'correlation-ablations.json')
    summary=dict(date='2026-11-13',frozen_implementation=FREEZE,synthetic=synthetic,synthetic_ablations=ablations,
                 historical_case_comparison=historical,real_development=real_summary(root),
                 correlation=dict(original_controls=len(control['records']),independent_real_edges=0,
                    counts_unchanged=all(r['findings_and_counts_unchanged'] for r in control['records']),
                    enabled_median_ms_range=[min(r['timings']['enabled']['median_ms'] for r in control['records']),max(r['timings']['enabled']['median_ms'] for r in control['records'])]),
                 independent_real_scorable_cases=0,reserved_source_opened=False)
    summary['staging_diagnostic']=read(root/'staging-diagnostic.json') if (root/'staging-diagnostic.json').exists() else None
    summary['tuning_regression']=read(root/'pysastbench-regression.json')['summary'] if (root/'pysastbench-regression.json').exists() else None
    write(root/'summary.json',summary)
    review_packet(root)
    artifacts={p.name:sha(json.dumps(read(p),sort_keys=True).encode()) for p in root.glob('*.json') if p.name!='artifact-hashes.json'}
    write(root/'artifact-hashes.json',dict(encoding='SHA-256 of json.dumps(value,sort_keys=True).encode(), independent of checkout line endings',artifacts=artifacts))
    return summary


def pct(value):
    return 'undefined' if value is None else f'{value*100:.2f}%'


def render(summary):
    diagnostic=summary.get('staging_diagnostic')
    staging_note=('The controlled old-stage Semgrep development replay reproduces the earlier 42 TP / 29 FP. '
                  'Exact-byte staging yields 49 TP / 31 FP, changing nine case outcomes (seven FN to TP, two TN to FP). '
                  'Validation/test Semgrep, all Bandit outcomes and all Theron outcomes are unchanged. '
                  'See staging-diagnostic.json; the primary comparison uses the corrected stage, not whichever run looks better.'
                  if diagnostic and diagnostic.get('old_stage_replay_matches_original_case_outcomes') else
                  'No verified controlled old-stage replay is available. Per-case differences from historical results are retained in summary.json.')
    lines=['# Step 5 frozen engineering results','',
        f"Implementation frozen at `{FREEZE}`. No detector/correlation/label/split tuning followed these outcomes.",'',
        '**This is exposed synthetic regression plus provisional development evidence. Zero real-code cases or graph edges have independent adjudication.** The nine real validation and nine real test candidates remain closed; the app and target applications were not started.','',
        '## Fresh exact-byte baseline comparison','',
        'The previous Windows baseline stage contained extra carriage returns. Fresh Bandit and Semgrep runs now use exact corpus bytes; native Linux input/rule hashes were verified. Older reports remain preserved. Historical per-case differences are retained in summary.json; old line-level provenance is not validated.','',
        '| Exposed split | Engine | TP | FN | FP | TN | Errors | Precision | Recall | F1 |',
        '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for split,tools in summary['synthetic'].items():
        for tool,data in tools.items():
            s=data['summary']
            lines.append(f"| {split} | {tool} | {s['tp']} | {s['fn']} | {s['fp']} | {s['tn']} | {s['errors']} | {pct(s['precision'])} | {pct(s['recall'])} | {pct(s['f1'])} |")
    lines += ['', 'All 1,230 cases and 14 categories remain included. Matching is the unchanged file/CWE adapter, not alert-level exploit precision or the official OWASP scorecard. Baseline support differs; raw unmatched-alert counts, errors, per-category outcomes and descriptive template-cluster intervals are preserved. Timing across Windows and WSL is not a performance ranking.','',
              staging_note,'',
              'Theron still has zero validation recall and lower test recall than both baselines. Fewer fixed-case matches at lower coverage do not establish superiority. These already-exposed splits are not fresh holdouts.','',
              '## Ablations','',
              '| Exposed split | Disabled feature | TP | FN | FP | TN |','| --- | --- | ---: | ---: | ---: | ---: |']
    for split,features in summary['synthetic_ablations'].items():
        for feature,s in features.items():
            lines.append(f"| {split} | {feature} | {s['tp']} | {s['fn']} | {s['fp']} | {s['tn']} |")
    lines += ['', 'Helper/import ablations each lose two development detections; disabling sanitizer models adds eight development fixed-case matches. All three remain neutral on exposed validation/test. No held-out benefit is attributed to neutral ablations.','',
              '## Seven real-code development pairs','',
              'Only the same 14 full-file snapshots were scanned. Four pairs have previously proposed target sink lines; three require more source/caller matching context. All seven remain represented. A match means a candidate matched the upstream CWE and proposed line, not an independently validated vulnerability. Patched-code candidates are not automatically false positives. All other alerts remain in compact baseline records.','',
              '| Case | Upstream snapshot role | Proposed sink | Theron default | Theron experimental | Bandit | Semgrep |',
              '| --- | --- | ---: | --- | --- | --- | --- |']
    for row in summary['real_development']['records']:
        values=[]
        for tool in ['theron_default','theron_experimental','bandit','semgrep']:
            result=row['outcomes'][tool]
            values.append('error' if result.get('errors') else 'context needed' if result['target_candidate'] is None else 'match' if result['target_candidate'] else 'no match')
        lines.append(f"| {row['cve_id']} | {row['role']} | {row['proposed_sink_line'] or 'unassigned'} | "+' | '.join(values)+' |')
    lines += ['', 'The real ablation records preserve every candidate and notice. Local-import ablation is structurally limited here because the probe scans isolated files without a repository index. Missing library callers/archive taint/untyped callback context remain failures, not excluded successes. Independent precision/recall is unavailable.','',
              '| Real development ablation | Default proposed matches, vulnerable / patched | Experimental proposed matches, vulnerable / patched |',
              '| --- | --- | --- |']
    for feature,modes in summary['real_development']['ablations'].items():
        lines.append(f"| {feature} | {modes['default']['vul_func']} / {modes['default']['fix_func']} | {modes['experimental']['vul_func']} / {modes['experimental']['fix_func']} |")
    lines += ['', 'Only four pairs have proposed target lines; these are candidate counts, not TP/FP rates. Disabling helper calls loses the OpenDiamond vulnerable-flow match. Sanitizer ablation is neutral here: the patched safe_join call is an unsupported return wrapper, not demonstrated explicit sanitizer handling. An original safe_join-to-shell control also misses CWE-78; see failure-probes.json. This is a future development fix, not a detector change hidden inside this evaluation.','',
              '## Correlation controls and cost','',
              f"Nine original author-labelled controls preserve findings, context and summary under enabled/disabled correlation: **{summary['correlation']['counts_unchanged']}**. Enabled-pass per-case median times range from {summary['correlation']['enabled_median_ms_range'][0]:.4f} to {summary['correlation']['enabled_median_ms_range'][1]:.4f} ms (one warm-up, 30 repetitions). These tiny controls do not establish scale, throughput or reviewer-time benefit.",'',
              'Bandit/Semgrep graph comparison is not applicable. The pilot adds inspectable relationships, not newly detected vulnerabilities or independent real-code edge validation.','',
              '## Remaining research gate','',
              'An output-blinded independent-review packet and separate upstream-role key are provided. A human reviewer must adjudicate sources, sinks, guards, eligibility and matching units; mark missing context unknown. No assistant-written draft has been counted as independent validation. No source/body from the real validation/test reserve was used.','',
              'The engineering comparison is complete. Publication-level independent real-code/edge accuracy and any claimed triage benefit remain unmeasured. No industry-readiness or publication-acceptance claim follows.','']
    return '\n'.join(lines)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory',type=Path,default=REPO/'docs/evaluation/step5-2026-11-13')
    args=p.parse_args()
    check_implementation()
    summary=summarize(args.directory)
    (args.directory/'RESULTS.md').write_text(render(summary),encoding='utf-8')
    print('Summary and review packet written; independently scorable real cases: 0')


if __name__=='__main__':
    main()
