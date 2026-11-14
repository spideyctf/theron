"""Conservative package-launch contracts. No package lookup, import or execution."""
import ast
import configparser
from email.parser import Parser
import hashlib
from pathlib import PurePosixPath
import re

from scanner.python_lock import canonical, tomllib


def package_launch(config_path, field, server, files):
    """Resolve supported uv run scripts / version-pinned uvx using collected metadata."""
    if not isinstance(server, dict) or server.get('command') not in {'uv', 'uvx'}:
        return None, 'unsupported_interpreter_or_wrapper', None
    if server.get('disabled') is True or server.get('enabled') is False:
        return None, 'server_explicitly_disabled', None
    if server.get('type', 'stdio') != 'stdio' or 'url' in server:
        return None, 'not_a_direct_stdio_declaration', None
    config = PurePosixPath(config_path)
    if config.name == 'mcp.json' and config.parent.name == '.vscode' and field == 'servers':
        root = config.parent.parent
        if server.get('cwd', '${workspaceFolder}') != '${workspaceFolder}':
            return None, 'unresolved_working_directory', None
    elif config.name == '.mcp.json' and field == 'mcpServers':
        root = config.parent
        if 'cwd' in server:
            return None, 'unresolved_working_directory', None
    else:
        return None, 'unknown_client_working_directory_or_variable_semantics', None
    if server.get('env'):
        return None, 'package_launch_environment_override_unresolved', None
    args = server.get('args')
    if not isinstance(args, list) or not args or any(not isinstance(a, str) for a in args):
        return None, 'invalid_or_missing_argument_vector', None
    requested = None
    if server['command'] == 'uv':
        if args[0] != 'run' or len(args) < 2 or args[1].startswith('-'):
            return None, 'unsupported_uv_invocation', None
        command = args[1]
        mode = 'local_project_script'
    else:
        if args[0] == '--from' and len(args) >= 3:
            requested, command = args[1:3]
        else:
            requested = args[0]
            command = requested.split('==')[0]
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*==\d+(?:\.\d+)+(?:[-+._][A-Za-z0-9.-]+)?', requested):
            return None, 'external_package_version_unresolved', None
        mode = 'collected_distribution_entrypoint_claim'
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', command):
        return None, 'unsupported_package_command', None
    declarations = []
    if mode == 'local_project_script':
        manifest = str(root / 'pyproject.toml')
        if manifest not in files or tomllib is None:
            return None, 'project_entrypoint_metadata_unavailable', None
        try:
            data = tomllib.loads(files[manifest])
            project = data.get('project', {})
            scripts = project.get('scripts', {})
            if not isinstance(scripts, dict) or not isinstance(project.get('name'), str):
                raise ValueError('invalid project metadata')
            # Custom build backends/source layouts may produce different import mappings.
            tools = data.get('tool', {})
            build = data.get('build-system', {})
            if not isinstance(build, dict) or build.get('build-backend') != 'setuptools.build_meta' or 'backend-path' in build:
                return None, 'project_installation_contract_unresolved', None
            uv = tools.get('uv', {}) if isinstance(tools, dict) else {}
            if not isinstance(uv, dict) or uv.get('package') is False:
                return None, 'project_installation_contract_unresolved', None
            if isinstance(tools, dict) and any(k in tools for k in ('hatch', 'poetry', 'pdm')):
                return None, 'custom_project_layout_unresolved', None
            setuptools = tools.get('setuptools', {}) if isinstance(tools, dict) else {}
            if isinstance(setuptools, dict) and any(k in setuptools for k in ('package-dir', 'packages', 'py-modules')):
                return None, 'custom_project_layout_unresolved', None
            target = scripts.get(command)
            if not isinstance(target, str):
                return None, 'project_script_not_declared', None
            declarations.append((target, manifest, root, project['name']))
        except (ValueError, TypeError, AttributeError):
            return None, 'malformed_project_entrypoint_metadata', None
    else:
        package, version = requested.split('==')
        for path, text in files.items():
            parent = PurePosixPath(path).parent
            if PurePosixPath(path).name != 'entry_points.txt' or not parent.name.endswith('.dist-info'):
                continue
            metadata = str(parent / 'METADATA')
            if metadata not in files:
                continue
            message = Parser().parsestr(files[metadata], headersonly=True)
            names, versions = message.get_all('Name', []), message.get_all('Version', [])
            if len(names) != 1 or len(versions) != 1 or canonical(str(names[0]).strip()) != canonical(package) or str(versions[0]).strip() != version:
                continue
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.optionxform = str
            try:
                parser.read_string(text)
                target = parser.get('console_scripts', command, fallback=None)
            except configparser.Error:
                return None, 'malformed_distribution_entrypoint_metadata', None
            if target:
                declarations.append((target, path, parent.parent, package))
    if len(declarations) != 1:
        return None, 'missing_or_ambiguous_package_entrypoint', None
    target, metadata, source_root, package = declarations[0]
    if not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*', target):
        return None, 'unsupported_entrypoint_object_reference', None
    module, function = target.split(':')
    candidates = []
    roots = [source_root, source_root / 'src'] if mode == 'local_project_script' else [source_root]
    for base in roots:
        relative = module.replace('.', '/')
        for path in (str(base / (relative + '.py')), str(base / relative / '__init__.py')):
            if path in files:
                candidates.append(path)
    if len(candidates) != 1:
        return None, 'missing_or_ambiguous_entrypoint_module', None
    path = candidates[0]
    module_parts = module.split('.')
    for index in range(1, len(module_parts)):
        if any(str(base / ('/'.join(module_parts[:index]) + '.py')) in files for base in roots):
            return None, 'entrypoint_import_shadow_unresolved', None
    try:
        tree = ast.parse(files[path])
        definitions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function]
        writes = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)) and n.id == function]
        imports = [a.asname or a.name.split('.')[0] for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names]
        if len(definitions) != 1 or definitions[0].decorator_list or writes or function in imports:
            return None, 'entrypoint_callable_unresolved', None
    except (SyntaxError, RecursionError):
        return None, 'entrypoint_python_unresolved', None
    evidence_paths = [metadata, path]
    if mode != 'local_project_script':
        from scanner.correlation_tools import distribution_claims
        claims = distribution_claims(files).get(module.split('.')[0], [])
        matching = [c for c in claims if canonical(c['package']) == canonical(package) and c['version'] == version and c['metadata'] == str(PurePosixPath(metadata).parent / 'METADATA')]
        if len(claims) != 1 or len(matching) != 1:
            return None, 'distribution_module_ownership_unresolved', None
        import csv, io
        record = matching[0]['record']
        listed = {r[0] for r in csv.reader(io.StringIO(files[record])) if r}
        if str(PurePosixPath(path).relative_to(source_root)) not in listed:
            return None, 'entrypoint_module_not_in_distribution_record', None
        evidence_paths += [matching[0]['metadata'], record]
    detail = dict(basis=mode, package=package, command=command, object_reference=target,
                  callable_file=path, callable_line=definitions[0].lineno,
                  installation_verified=False, startup_verified=False,
                  source_text_sha256={p: hashlib.sha256(files[p].encode()).hexdigest() for p in evidence_paths})
    return path, 'package_entrypoint_inferred', detail
