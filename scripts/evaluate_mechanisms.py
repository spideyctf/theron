"""Separate exposed-development replay; previous frozen results stay untouched."""
from scripts.evaluate_final_realcode import ROOT
from scripts.evaluate_obligations import evaluate

FREEZE='6eb6aee2e554c52a5f7519f0f7b6bed016f56f1a'
OUT=ROOT/'docs/evaluation/mechanisms-2026-11-14'


def main():
    evaluate(OUT,FREEZE,source_guided=True)


if __name__=='__main__':main()
