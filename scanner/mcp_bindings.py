"""Explicit hash-bound local implementation claims for otherwise unmapped launches."""
import hashlib
from pathlib import PurePosixPath, PureWindowsPath
import re
from urllib.parse import urlsplit


def validate_bindings(bindings):
    if not isinstance(bindings, list) or len(bindings) > 100:
        raise ValueError('mcp_bindings must be a list of at most 100 mappings')
    seen = set()
    required = {'config_file', 'pointer', 'entrypoint', 'config_sha256', 'entrypoint_sha256', 'kind', 'reason'}
    for item in bindings:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError('Each MCP binding requires config_file, pointer, entrypoint, both SHA256 hashes, kind and reason')
        for key in ('config_file', 'entrypoint'):
            value = item[key]
            if not isinstance(value, str) or not value or '\\' in value or ':' in value or PurePosixPath(value).is_absolute() or any(p in {'', '.', '..'} for p in value.split('/')):
                raise ValueError('MCP binding paths must be repository-relative without traversal')
        if not item['entrypoint'].endswith('.py') or item['kind'] not in ('http', 'absolute-python'):
            raise ValueError('MCP bindings require a Python entrypoint and http or absolute-python kind')
        for key in ('config_sha256', 'entrypoint_sha256'):
            if not isinstance(item[key], str) or not re.fullmatch('[a-f0-9]{64}', item[key]):
                raise ValueError('MCP binding hashes must be lowercase SHA256 digests')
        if not isinstance(item['pointer'], str) or not item['pointer'].startswith(('/servers/', '/mcpServers/', '/mcp_servers/')) or len(item['pointer']) > 1000:
            raise ValueError('MCP binding pointer must identify a server declaration')
        if not isinstance(item['reason'], str) or not item['reason'].strip() or len(item['reason']) > 2000:
            raise ValueError('MCP binding reason must be nonempty, at most 2000 characters')
        key = (item['config_file'], item['pointer'])
        if key in seen:raise ValueError('Duplicate MCP binding')
        seen.add(key)
    return bindings


def bind_source(binding, server, files):
    if not isinstance(server, dict) or server.get('disabled') is True or server.get('enabled') is False:
        return None, 'binding_declaration_disabled_or_invalid', None
    for path_key, hash_key in (('config_file', 'config_sha256'), ('entrypoint', 'entrypoint_sha256')):
        path = binding[path_key]
        if path not in files:return None, 'binding_source_not_collected', None
        if hashlib.sha256(files[path].encode()).hexdigest() != binding[hash_key]:
            return None, 'binding_source_digest_mismatch', None
    if binding['kind'] == 'http':
        try:
            url = urlsplit(server.get('url', ''))
            valid = url.scheme in ('http', 'https') and bool(url.hostname) and not url.username and not url.password and not url.fragment
            valid = valid and server.get('type', 'http') in ('http', 'sse') and 'command' not in server
        except (ValueError, TypeError, AttributeError):valid = False
    else:
        command, args = server.get('command'), server.get('args')
        valid = isinstance(command, str) and isinstance(args, list) and bool(args) and all(isinstance(a, str) for a in args)
        if valid:
            absolute = lambda value: PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()
            executable = command.replace('\\', '/').split('/')[-1]
            rest = list(args)
            while rest and rest[0] in ('-u', '-B'):rest.pop(0)
            valid = absolute(command) and bool(re.fullmatch(r'python(?:3(?:\.\d{1,2})?)?(?:\.exe)?', executable)) and bool(rest) and absolute(rest[0]) and rest[0].endswith('.py')
            valid = valid and server.get('type', 'stdio') == 'stdio' and 'url' not in server
    if not valid:return None, 'binding_launch_contract_mismatch', None
    detail = dict(basis='explicit_hash_bound_source_claim', kind=binding['kind'], reason=binding['reason'],
        source_text_sha256={binding['config_file']:binding['config_sha256'], binding['entrypoint']:binding['entrypoint_sha256']},
        runtime_verified=False, remote_identity_verified=False)
    return binding['entrypoint'], 'explicit_implementation_source_bound', detail
