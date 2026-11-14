"""Final optimized synthetic replay; the separate timed smoke is not repeated here."""
from scripts import check_obligation_regressions as regression
from scripts.evaluate_mechanisms import OUT
from scripts.check_mechanism_optimization import OPTIMIZATION


if __name__=='__main__':
    regression.OUT=OUT/'final-regression'
    regression.FREEZE=OPTIMIZATION
    regression.main(run_smoke=False)
