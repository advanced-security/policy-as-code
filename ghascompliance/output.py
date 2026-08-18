import json
import os
from typing import Any, Dict


def write_results(
    path: str,
    total_violations: int,
    total_errors: int,
    checks: Dict[str, Dict[str, Any]],
) -> None:
    """Write policy check results to a JSON file.

    Args:
        path: File path to write the JSON results to. Missing parent
            directories are created.
        total_violations: Total number of policy violations found by the
            checks that ran successfully.
        total_errors: Number of checks that failed with an error.
        checks: Per-check results, keyed by check name, each containing the
            check `status`, its `violations` count and, on failure, an `error`.
    """
    output_directory = os.path.dirname(path)
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "schema_version": 1,
                "total_violations": total_violations,
                "total_errors": total_errors,
                "checks": checks,
            },
            handle,
            indent=2,
        )
        handle.write("\n")
