"""
Machine-readable JSON assessment report generator.
"""

import os
import json
from wadix.reporting.models import ScanSummary

def generate_json_report(summary: ScanSummary, file_path: str) -> str:
    """Generate structured JSON report for automation and SIEM ingestion."""
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    data = summary.to_dict()

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return file_path
