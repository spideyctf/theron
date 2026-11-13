"""Bounded offline subprocess measurements and in-process API contract exercise."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'docs/evaluation/final-validation-2026-11-13'


def peak_memory():
    if sys.platform == 'win32':
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ['PeakWorkingSetSize', 'WorkingSetSize', 'QuotaPeakPagedPoolUsage',
                'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage']]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL('psapi', use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return counters.PeakWorkingSetSize
    import resource
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value if sys.platform == 'darwin' else value * 1024


def worker(count, destination):
    from scanner.correlation import correlate
    from scanner.finding_utils import normalize_findings, partition_findings
    from scanner.models import ScanContext, ScanResult
    from scanner.plugins.sast import SASTScanner
    from scanner.profiler import ProjectProfiler
    from scanner.reporters.html import generate_html_report
    from scanner.reporters.json_reporter import generate_json_report
    from scanner.reporters.sarif import generate_sarif_report
    from scanner.rule_loader import RuleLoader
    started = time.perf_counter()
    corpus = ROOT/'.benchmark-cache/BenchmarkPython'
    paths = sorted((corpus/'testcode').rglob('*.py'))[:count]
    if len(paths) != count:
        raise ValueError('Insufficient predefined corpus files')
    files = {p.relative_to(corpus).as_posix(): p.read_text(encoding='utf-8-sig') for p in paths}
    profile = ProjectProfiler().analyze(files)
    findings = SASTScanner().scan(ScanContext(files, {}, profile, RuleLoader(), {}))
    result = ScanResult(repo_full_name='operational/exposed-owasp', branch='pinned', files_scanned=len(files),
                        findings=normalize_findings(findings), project_profile=profile.to_dict(), modules_run=['sast'])
    partition_findings(result)
    correlate(result, files, True)
    export_sizes = {fmt: len(generate(result).encode()) for fmt, generate in [
        ('json', generate_json_report), ('html', generate_html_report), ('sarif', generate_sarif_report)]}
    payload = dict(count=count, measured_pipeline_seconds=time.perf_counter()-started,
        peak_process_working_set_bytes=peak_memory(), total_findings=len(result.findings),
        informational_notices=sum(f.severity.value=='INFO' for f in result.findings),
        fingerprint_sha256=hashlib.sha256(json.dumps(sorted(f.fingerprint for f in result.findings)).encode()).hexdigest(),
        export_bytes=export_sizes, input_sha256={p.relative_to(corpus).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    destination.write_text(json.dumps(payload, indent=2)+'\n', encoding='utf-8')


def p95(values):
    return sorted(values)[math.ceil(len(values)*.95)-1]


def api_contract():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from fastapi.testclient import TestClient
    from scanner.web import create_app
    from tests.flow_delivery_fixture import build
    started, release = Event(), Event()
    class ControlledEngine:
        def __init__(self, *args, **kwargs):
            pass
        def scan_repo(self, owner, repo, **kwargs):
            started.set()
            if not release.wait(15):
                raise RuntimeError('Controlled queue did not release')
            if repo=='fail':
                raise ValueError('operational-token-must-stay-private')
            return build()[1]
    old_token = os.environ.get('GITHUB_TOKEN')
    os.environ['GITHUB_TOKEN'] = 'operational-token-must-stay-private'
    try:
        with TestClient(create_app(scanner_factory=ControlledEngine)) as client:
            ids = []
            try:
                for i in range(10):
                    response = client.post('/api/scans', json={'repository':'owner/fail' if i==4 else 'owner/repo','modules':['sast']})
                    assert response.status_code == 202
                    ids.append(response.json()['id'])
                assert started.wait(2)
                overflow = client.post('/api/scans', json={'repository':'owner/overflow','modules':['sast']})
                assert overflow.status_code == 429
                assert client.get('/api/scans/'+ids[0]+'/report').status_code == 409
                def health(_):
                    begin = time.perf_counter()
                    assert client.get('/api/health').status_code == 200
                    return time.perf_counter()-begin
                with ThreadPoolExecutor(max_workers=4) as pool:
                    timings = list(pool.map(health, range(40)))
            finally:
                release.set()
            deadline = time.monotonic()+15
            while True:
                jobs = [client.get('/api/scans/'+id).json() for id in ids]
                if all(j['status'] in {'completed','failed'} for j in jobs):
                    break
                if time.monotonic()>deadline:
                    raise AssertionError('Queue did not drain')
                time.sleep(.01)
            assert sum(j['status']=='completed' for j in jobs)==9
            assert sum(j['status']=='failed' for j in jobs)==1
            assert 'operational-token-must-stay-private' not in json.dumps(jobs)
            for id in [ids[0],ids[-1]]:
                for fmt in ['json','sarif']:
                    assert client.get('/api/scans/'+id+'/report?format='+fmt).status_code==200
            recovery = client.post('/api/scans', json={'repository':'owner/recovered','modules':['sast']})
            assert recovery.status_code==202
            recovered_id = recovery.json()['id']
            deadline = time.monotonic()+15
            while client.get('/api/scans/'+recovered_id).json()['status']!='completed':
                if time.monotonic()>deadline:
                    raise AssertionError('Recovery job did not complete')
                time.sleep(.01)
            return dict(accepted_initial_jobs=10, overflow_status=429, completed_jobs=9, failed_jobs=1,
                queue_recovery_accepted=True, queue_recovery_completed=True, failure_secret_redacted=True, downloads_verified=4,
                concurrent_health_requests=40, health_median_seconds=statistics.median(timings), health_p95_seconds=p95(timings),
                transport='in-process controlled scanner; no live GitHub or server', live_application_started=False)
    finally:
        if old_token is None:
            os.environ.pop('GITHUB_TOKEN', None)
        else:
            os.environ['GITHUB_TOKEN'] = old_token


def measure():
    from scripts.evaluate_final_realcode import cases, write
    cases()  # Verify the detector and original manifest freeze.
    cache = ROOT/'.benchmark-cache/final-operations'
    cache.mkdir(exist_ok=True)
    records = []
    for count in [25,100,250]:
        for repetition in range(3):
            destination = cache/f'{count}-{repetition}.json'
            begin = time.perf_counter()
            try:
                completed = subprocess.run([sys.executable, '-m', 'scripts.evaluate_operations', '--worker',str(count),'--output',str(destination)],
                    cwd=ROOT, capture_output=True, text=True, timeout=120)
                if completed.returncode:
                    raise RuntimeError(completed.stderr[-1500:])
                row = json.loads(destination.read_text())
                row.update(repetition=repetition, fresh_process_wall_seconds=time.perf_counter()-begin)
            except (subprocess.TimeoutExpired, RuntimeError, OSError) as exc:
                row = dict(count=count, repetition=repetition, error=type(exc).__name__+': '+str(exc))
            records.append(row)
            print(count, repetition, row.get('fresh_process_wall_seconds',row.get('error')), flush=True)
    summaries = []
    for count in [25,100,250]:
        rows = [r for r in records if r['count']==count and 'error' not in r]
        stable = len({(r['fingerprint_sha256'],json.dumps(r['export_bytes'],sort_keys=True),json.dumps(r['input_sha256'],sort_keys=True)) for r in rows})==1
        summaries.append(dict(count=count, successes=len(rows), errors=3-len(rows), deterministic_outputs=stable,
            wall_median_seconds=statistics.median([r['fresh_process_wall_seconds'] for r in rows]) if rows else None,
            wall_p95_seconds=p95([r['fresh_process_wall_seconds'] for r in rows]) if rows else None,
            peak_memory_bytes=max([r['peak_process_working_set_bytes'] for r in rows],default=None)))
    api = api_contract()
    write(OUT/'operations.json', dict(implementation_revision='4c166e0b179e1ff10a3a432e2bd439765b601a81',
        python=sys.version, platform=platform.platform(), cpu_count=os.cpu_count(), cpu=platform.processor(),
        timing_scope='Fresh-process wall time; uncontrolled local OS cache, three repetitions. p95 is empirical maximum at n=3.',
        memory_scope='Peak process working set, including interpreter/imports; no scanned code executed',
        corpus_revision='f1291485808b66e20ddb6b01b10dc71b3df8c8ba',
        modules_measured=['sast'], excludes=['SCA advisory network','live GitHub transport','multiuser deployment','AI/agentic accuracy'],
        records=records, summary=summaries, api_contract=api))
    print(json.dumps(dict(summary=summaries,api=api),indent=2),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',type=int)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.worker:
        if args.worker not in {25,100,250} or args.output is None:
            raise ValueError('Only predefined operational sizes are accepted')
        worker(args.worker,args.output)
    else:
        measure()
