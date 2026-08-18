import json
import os
import tempfile
import unittest

from ghascompliance.output import write_results


class TestOutput(unittest.TestCase):
    def test_write_results_creates_structured_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "results", "output.json")

            write_results(path, 2, {"code_scanning": 1, "dependabot": 1})

            with open(path, encoding="utf-8") as handle:
                self.assertEqual(
                    json.load(handle),
                    {
                        "schema_version": 1,
                        "total_violations": 2,
                        "checks": {"code_scanning": 1, "dependabot": 1},
                    },
                )
