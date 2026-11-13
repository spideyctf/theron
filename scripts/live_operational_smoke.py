"""One all-module GitHub/OSV smoke test against Theron's public frozen commit."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import subprocess
import time
from urllib.parse import urlparse

import requests

from scanner.engine import ScanEngine
from scanner.reporters.json_reporter import generate_json_report
from scanner.reporters.html import generate_html_report
from scanner.reporters.sarif import generate_sarif_report
from scripts.evaluate_final_realcode import FREEZE, ROOT, OUT, CACHE, write
from scripts.evaluate_operations import peak_memory


def main(implementation_revision=FREEZE):
    if subprocess.run(['git','diff','--quiet',implementation_revision,'--','scanner','rules'],cwd=ROOT).returncode:
        raise ValueError('Declared operational implementation changed')
    name='live-selfscan' if implementation_revision==FREEZE else 'live-selfscan-repaired'
    login=subprocess.check_output(['gh','api','user','--jq','.login'],text=True).strip()
    if login!='spideyctf':
        raise ValueError('Use spideyctf only')
    token=subprocess.check_output(['gh','auth','token'],text=True,stderr=subprocess.PIPE).strip()
    original=requests.Session.request
    network=[]
    def observed(session,method,url,*args,**kwargs):
        begin=time.perf_counter()
        item=dict(method=method,host=urlparse(url).hostname)
        try:
            response=original(session,method,url,*args,**kwargs)
            item.update(status=response.status_code,response_bytes=len(response.content),
                response_sha256=hashlib.sha256(response.content).hexdigest())
            return response
        except requests.RequestException as exc:
            item['error_type']=type(exc).__name__
            raise
        finally:
            item['seconds']=time.perf_counter()-begin
            network.append(item)
    requests.Session.request=observed
    started=datetime.now(timezone.utc).isoformat()
    begin=time.perf_counter()
    engine=ScanEngine(token,config={'include_experimental':False,'correlation_enabled':True})
    try:
        result=engine.scan_repo('spideyctf','theron',branch=FREEZE,modules=['ai','sast','sca','agentic'])
    except Exception as exc:
        import traceback
        write(OUT/(name+'-failure.json'),dict(implementation_revision=implementation_revision,target_revision=FREEZE,
            status='failed',error_type=type(exc).__name__,observed_utc=started,wall_seconds=time.perf_counter()-begin,
            network_requests=network,frames=[dict(file=frame.filename.replace('\\','/').rsplit('/',1)[-1],line=frame.lineno,function=frame.name)
            for frame in traceback.extract_tb(exc.__traceback__)],target_code_executed=False))
        raise
    finally:
        requests.Session.request=original
        engine.github.session.close()
    if result.commit_sha!=FREEZE or set(result.modules_run)!={'ai','sast','sca','agentic'}:
        raise AssertionError('Snapshot or module coverage differs')
    exports={}
    for fmt,generate in [('json',generate_json_report),('html',generate_html_report),('sarif',generate_sarif_report)]:
        text=generate(result)
        (CACHE/(name+'.'+fmt)).write_text(text,encoding='utf-8')
        exports[fmt]=dict(bytes=len(text.encode()),sha256=hashlib.sha256(text.encode()).hexdigest())
    def compact(f):
        data=f.to_dict()
        return {k:data[k] for k in ['rule_id','file_path','line_number','severity','maturity','evidence_kind','scope','fingerprint']}
    components=(result.sbom or {}).get('components',[])
    report=dict(implementation_revision=implementation_revision,target='spideyctf/theron',target_revision=result.commit_sha,
        observed_utc=started,wall_seconds=time.perf_counter()-begin,engine_seconds=result.scan_duration_seconds,
        peak_process_working_set_bytes=peak_memory(),modules_run=result.modules_run,summary=result.summary,
        application_findings=[compact(f) for f in result.findings],context_findings=[compact(f) for f in result.context_findings],
        sbom_components=len(components),unresolved_sbom_versions=sum(not c.get('version') for c in components),
        network_requests=network,network_status_counts=dict(Counter(str(r.get('status',r.get('error_type'))) for r in network)),
        exports=exports,target_code_executed=False,live_application_started=False,
        interpretation='One live static GitHub/OSV smoke run on the tool itself; not accuracy, repeatable advisory ground truth, load capacity or proof of security.')
    write(OUT/(name+'.json'),report)
    print({k:report[k] for k in ['wall_seconds','summary','sbom_components','unresolved_sbom_versions','network_status_counts']},flush=True)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--implementation',choices=[FREEZE,'cfbfb83db97e468035a23c7ad19c0597bb46c317'],default=FREEZE)
    main(parser.parse_args().implementation)
