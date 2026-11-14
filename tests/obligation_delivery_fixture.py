"""Original inert sources exercise all three required-condition evidence families."""
from tests.test_security_obligations import AUTH, PROTO
from scanner.models import ScanContext, ScanResult, ProjectProfile
from scanner.plugins.sast import SASTScanner
from scanner.rule_loader import RuleLoader
from scanner.finding_utils import normalize_findings


def source_files():
    return {
        'views.py':AUTH.format(body='  return get_object_or_404(self.get_queryset(),pk=1)'),
        'tokens.py':'import jwt\njwt.decode(token,key,algorithms=["RS256"],options={"verify_signature":False})',
        'reader.py':PROTO.format(initial='0',pending='2',body='  data=buf.maybe_extract_at_most(self.pending)\n  self.pending-=len(data)'),
    }


def build():
    files=source_files()
    fs=SASTScanner().scan(ScanContext(files,{},ProjectProfile(),RuleLoader(),{}))
    return ScanResult(repo_full_name='owner/obligations',branch='main',commit_sha='a'*40,
        findings=normalize_findings(fs),files_scanned=len(files),modules_run=['sast'])
