"""Bounded MCP declaration-to-code evidence. Never executes declared commands."""
from collections import defaultdict
import hashlib
import json
from pathlib import PurePosixPath
import re

from scanner.finding_utils import finding_scope


CONFIG_NAMES = {'mcp.json', '.mcp.json', 'mcp_config.json', 'mcp_servers.json',
                'claude_desktop_config.json', 'claude_code_config.json', 'mcp-config.json'}
FLOW_RULES = {'PY-SAST-EXEC-001', 'PY-AI-EXEC-001', 'PY-AI-MODEL-001', 'PY-SAST-SQL-001',
              'PY-SAST-PATH-001', 'PY-SAST-XPATH-001', 'PY-SAST-REDIRECT-001', 'PY-SAST-SSRF-001', 'PY-SAST-XSS-001'}
LIMITATIONS = [
    'Workspace binding is inferred from the configuration location, not verified in a running MCP client.',
    'Code presence and static flow do not establish startup or callback reachability.',
    'Network exposure, authentication, effective privileges and exploitability remain unknown.',
    'No declared command or scanned module was executed. Groups do not add vulnerability counts or severity.',
]


def _object(pairs):
    result = {}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result

def _invalid_constant(value):
    raise ValueError('Non-JSON constant')


def _path(value):
    if not isinstance(value,str) or not value or any(ord(c)<32 for c in value):
        return None
    value = value.replace('\\','/')
    if value.startswith(('/', '~')) or any(c in value for c in '$%:'):
        return None
    if '..' in value.split('/'):
        return None
    return PurePosixPath(value).as_posix()


def _resolve(config_path, field, server):
    if not isinstance(server,dict):
        return None, 'invalid_server_object'
    if server.get('disabled') is True or server.get('enabled') is False:
        return None, 'server_explicitly_disabled'
    if server.get('type','stdio') != 'stdio' or 'url' in server:
        return None, 'not_a_direct_stdio_declaration'
    if not isinstance(server.get('command'),str) or not re.fullmatch(r'python(?:3(?:\.\d{1,2})?)?(?:\.exe)?',server['command']):
        return None, 'unsupported_interpreter_or_wrapper'
    args = server.get('args')
    if not isinstance(args,list) or not args or any(not isinstance(a,str) for a in args):
        return None, 'invalid_or_missing_argument_vector'
    args = list(args)
    while args and args[0] in {'-u','-B'}:
        args.pop(0)
    if not args or args[0].startswith('-'):
        return None, 'unsupported_python_invocation'
    config = PurePosixPath(config_path)
    if config.parent.name != '.vscode' or config.name != 'mcp.json' or field != 'servers':
        return None, 'unknown_client_working_directory_or_variable_semantics'
    if server.get('type') != 'stdio':
        return None, 'missing_or_invalid_stdio_type'
    workspace = config.parent.parent.as_posix()
    cwd = server.get('cwd','${workspaceFolder}')
    if not isinstance(cwd,str) or not (cwd == '${workspaceFolder}' or cwd.startswith('${workspaceFolder}/')):
        return None, 'unresolved_working_directory'
    relative_cwd = _path(cwd[len('${workspaceFolder}'):].lstrip('/') or '.')
    if relative_cwd is None:
        return None, 'working_directory_outside_workspace_or_dynamic'
    script = args[0]
    if script.startswith('${workspaceFolder}/'):
        script = _path(script[len('${workspaceFolder}/'):])
        base = workspace
    else:
        script = _path(script)
        base = str(PurePosixPath(workspace)/relative_cwd)
    if script is None or not script.endswith('.py'):
        return None, 'unsupported_or_outside_python_path'
    candidate = _path(str(PurePosixPath(base)/script))
    return candidate, 'workspace_binding_inferred' if candidate else 'unsupported_workspace_path'


def correlate(result, files, enabled=True):
    """Attach additive report-local groups after normalization/partitioning."""
    result.correlation_enabled = enabled
    result.correlation_groups, result.correlation_resolutions = [], []
    if not enabled:
        return
    paths = defaultdict(list)
    for path in files:
        normalized = _path(path)
        if normalized:
            paths[normalized.casefold()].append((normalized,path))
    flows = defaultdict(list)
    for finding in result.findings + result.context_findings:
        if finding.rule_id not in FLOW_RULES or finding.evidence_kind != 'static-flow' or not finding.fingerprint or finding.severity == 'INFO':
            continue
        trace = finding.trace
        if not trace or any(not isinstance(t,dict) or t.get('role') not in {'source','sink'} or t.get('file_path') not in files
                            or type(t.get('line_number')) is not int
                            or not 0 < t['line_number'] <= len(files[t['file_path']].splitlines()) for t in trace):
            continue
        if not any(t.get('role')=='source' for t in trace) or not any(
                t.get('role')=='sink' and t['file_path']==finding.file_path and t['line_number']==finding.line_number for t in trace):
            continue
        flows[finding.file_path].append(finding)
    for config_path,content in sorted(files.items()):
        if PurePosixPath(config_path.replace('\\','/')).name not in CONFIG_NAMES:
            continue
        def resolution(pointer,reason,entrypoint=None,status='unresolved'):
            row=dict(config_file=config_path,pointer=pointer,status=status,reason=reason,entrypoint=entrypoint,
                     classification='inferred' if status=='resolved' else 'unknown',scope=finding_scope(config_path),group_ids=[])
            result.correlation_resolutions.append(row)
            return row
        try:
            data=json.loads(content,object_pairs_hook=_object,parse_constant=_invalid_constant)
            fields=[key for key in ('servers','mcpServers','mcp_servers') if isinstance(data,dict) and key in data]
            if len(fields)!=1 or not isinstance(data[fields[0]],dict):
                resolution('', 'missing_or_ambiguous_server_mapping')
                continue
        except (ValueError,RecursionError):
            resolution('', 'malformed_or_duplicate_key_json')
            continue
        field=fields[0]
        for name,server in sorted(data[field].items()):
            pointer='/'+field+'/'+name.replace('~','~0').replace('/','~1')
            entrypoint,reason=_resolve(config_path,field,server)
            row=resolution(pointer,reason)
            if entrypoint is None:
                continue
            row['entrypoint']=entrypoint
            candidates=paths.get(entrypoint.casefold(),[])
            if len(candidates)>1:
                row['reason']='ambiguous_collected_path'
                continue
            if not candidates or candidates[0][0]!=entrypoint:
                row['reason']='target_not_collected_with_exact_case'
                continue
            target=candidates[0][1]
            row.update(status='resolved',classification='inferred',entrypoint=target)
            members=sorted(flows.get(target,[]),key=lambda f:f.fingerprint)
            if not members:
                row['reason']='no_eligible_flow_evidence_in_entrypoint'
                continue
            refs=sorted({f.fingerprint for f in members})
            identity=[result.repo_full_name,result.commit_sha,result.branch,config_path,pointer,target,refs]
            group_id='mcp-flow-'+hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()[:24]
            declaration=dict(kind='configuration',file_path=config_path,pointer=pointer)
            entry=dict(kind='file',file_path=target)
            scopes=[finding_scope(config_path)]+[f.scope for f in members]
            result.correlation_groups.append(dict(id=group_id,title='Declared MCP entrypoint contains a supported code flow',
                scope=next((s for s in scopes if s!='application'),'application'),classification='inferred',maturity='experimental',
                finding_fingerprints=refs,limitations=list(LIMITATIONS),relationships=[
                    dict(kind='declares_entrypoint',source=declaration,target=entry,classification='inferred',
                         evidence=[dict(file_path=config_path,pointer=pointer+'/args')])]+[
                    dict(kind='entrypoint_contains_flow',source=entry,target=dict(kind='finding',fingerprint=f.fingerprint),
                         classification='observed',evidence=[{k:t[k] for k in ('role','file_path','line_number')} for t in f.trace],
                         confidence=f.confidence,maturity=f.maturity) for f in members]))
            row['group_ids']=[group_id]
