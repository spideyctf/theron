"""JSON reporter — outputs machine-readable JSON scan results."""

import json
from scanner.models import ScanResult


def generate_json_report(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, default=str)


def save_json_report(result: ScanResult, output_path: str):
    with open(output_path, "w") as f:
        f.write(generate_json_report(result))
