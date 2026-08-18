import json
import os
from typing import Dict


def write_results(path: str, total_violations: int, checks: Dict[str, int]) -> None:
    """Write policy check results to a JSON file."""
    output_directory = os.path.dirname(path)
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "schema_version": 1,
                "total_violations": total_violations,
                "checks": checks,
            },
            handle,
            indent=2,
        )
