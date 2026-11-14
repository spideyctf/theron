"""Replay existing exposed regressions into the separate mechanism checkpoint."""
from scripts import check_obligation_regressions as regression
from scripts.evaluate_mechanisms import OUT,FREEZE


if __name__=='__main__':
    regression.OUT=OUT
    regression.FREEZE=FREEZE
    regression.main()
