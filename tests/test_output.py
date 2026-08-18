import json
import os
import tempfile
import unittest

from ghascompliance.output import write_results


class TestOutput(unittest.TestCase):
    def test_write_results_creates_structured_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "results", "output.json")

            write_results(
                path,
                2,
                1,
                {
                    "code_scanning": {"status": "success", "violations": 1},
                    "dependabot": {"status": "success", "violations": 1},
                    "secret_scanning": {
                        "status": "error",
                        "violations": 0,
                        "error": "Authentication Error",
                    },
                },
            )

            with open(path, encoding="utf-8") as handle:
                self.assertEqual(
                    json.load(handle),
                    {
                        "schema_version": 1,
                        "total_violations": 2,
                        "total_errors": 1,
                        "checks": {
                            "code_scanning": {"status": "success", "violations": 1},
                            "dependabot": {"status": "success", "violations": 1},
                            "secret_scanning": {
                                "status": "error",
                                "violations": 0,
                                "error": "Authentication Error",
                            },
                        },
                    },
                )

    def test_write_results_ends_with_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "output.json")

            write_results(path, 0, 0, {})

            with open(path, encoding="utf-8") as handle:
                self.assertTrue(handle.read().endswith("\n"))
