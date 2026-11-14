"""Reuse exact-byte pinned baseline machinery for the separately registered pilot."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import compare_obligation_baselines as baseline
baseline.OUT=ROOT/'docs/evaluation/mechanisms-2026-11-14/vul4py'
baseline.CACHE=ROOT/'.benchmark-cache/vul4py-baselines'
baseline.SOURCE_CACHE=ROOT/'.benchmark-cache/vul4py-pilot'

if __name__=='__main__':
    {'stage':baseline.stage,'verify-native':baseline.verify_native,'compare':baseline.compare}[sys.argv[1]]()
