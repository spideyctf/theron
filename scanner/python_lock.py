"""Read a bounded uv.lock v1 inventory as data, never as an installed environment."""
import hashlib
import re
try:
    import tomllib
except ImportError:
    tomllib = None


def canonical(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def uv_inventory(content):
    """Return name/version/provenance rows; ambiguous or non-PyPI rows have no version."""
    if tomllib is None:
        raise ValueError('TOML parsing unavailable on this Python runtime')
    data = tomllib.loads(content)
    if type(data.get('version')) is not int or data['version'] != 1:
        raise ValueError('Unsupported uv.lock schema version')
    revision = data.get('revision', 0)
    if type(revision) is not int or not 0 <= revision <= 3:
        raise ValueError('Unsupported uv.lock schema revision')
    packages = data.get('package')
    if not isinstance(packages, list) or len(packages) > 10000:
        raise ValueError('Missing or oversized uv.lock package inventory')
    rows = []
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError('Malformed uv.lock package')
        name = package.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name):
            raise ValueError('Malformed uv.lock package name')
        version, source = package.get('version'), package.get('source')
        markers = package.get('resolution-markers', [])
        if not isinstance(markers, list) or any(not isinstance(m, str) for m in markers):
            raise ValueError('Malformed uv.lock resolution markers')
        registry = source.get('registry') if isinstance(source, dict) and set(source) == {'registry'} else None
        reason = None
        if registry not in ('https://pypi.org/simple', 'https://pypi.org/simple/'):
            reason = 'non_pypi_or_local_source'
        elif markers:
            reason = 'conditional_resolution_without_target_environment'
        elif not isinstance(version, str) or not re.fullmatch(r'\d+(?:\.\d+)+(?:[-+._][A-Za-z0-9.-]+)?', version):
            reason = 'unsupported_exact_version'
        rows.append(dict(name=name, version=version if reason is None else None,
                         declared_version=version if isinstance(version, str) else None,
                         status=reason or 'exact_lock_inventory', resolution_markers=markers,
                         provenance=dict(format='uv.lock', schema_version=1, schema_revision=revision,
                             source_kind='pypi_registry' if registry else 'other',
                             source_text_sha256=hashlib.sha256(content.encode()).hexdigest(),
                             installation_verified=False)))
    counts = {}
    for row in rows:
        key = canonical(row['name'])
        counts[key] = counts.get(key, 0) + 1
    for row in rows:
        if counts[canonical(row['name'])] > 1:
            row.update(version=None, status='multiple_lock_variants_without_target_environment')
    return rows
