import unittest

from ghastoolkit import CodeAlert
from ghascompliance.policies.base import PolicyV3
from ghascompliance.policies.severities import SeverityLevelEnum


def createAlert(
    tool="CodeQL",
    severity="error",
    rule_id="py/sqli",
    created_at="2020-06-19T11:21:34Z",
) -> CodeAlert:
    """Create an alert helper."""
    return CodeAlert(
        42,
        "open",
        created_at,
        rule={"id": rule_id, "security_severity_level": severity},
        tool={"name": tool},
    )


class TestCodeScanningChecker(unittest.TestCase):
    def setUp(self) -> None:
        self.root_policy = PolicyV3()
        self.policy = self.root_policy.codescanning[0]

        from ghascompliance.checks.codescanning import CodeScanningChecker

        self.checker = CodeScanningChecker("Code Scanning", self.policy)
        # manually set severities
        self.checker.severities = SeverityLevelEnum.getSeveritiesFromName(
            self.policy.severity.value
        )
        return super().setUp()

    def test_alert_severity(self):
        """Check severity matches."""
        # changes the state
        self.checker.checkCodeScanningAlert(self.policy, createAlert(severity="error"))
        self.assertEqual(len(self.checker.state.errors), 1)
        error = self.checker.state.errors.pop(0)
        self.assertEqual(error.get("trigger"), "severity")

    def test_alert_id(self):
        """Check ID matches."""
        self.policy.ids = ["py/sqli", "py/xss"]

        self.checker.checkCodeScanningAlert(
            self.policy, createAlert(severity="warning", rule_id="py/sqli")
        )
        self.assertEqual(len(self.checker.state.errors), 1)
        error = self.checker.state.errors.pop(0)
        self.assertEqual(error.get("trigger"), "id-match")

        # reset
        self.checker.state.reset()

        # does not match a rule
        self.checker.checkCodeScanningAlert(
            self.policy, createAlert(severity="warning", rule_id="py/sample")
        )
        self.assertEqual(len(self.checker.state.errors), 0)

    def test_alert_id_ignored(self):
        self.policy.ids_ignores = ["py/sqli", "py/xss"]

        self.checker.checkCodeScanningAlert(
            self.policy, createAlert(severity="warning", rule_id="py/sqli")
        )
        self.assertEqual(len(self.checker.state.ignored), 1)
        ignore = self.checker.state.ignored.pop(0)
        self.assertEqual(ignore.get("trigger"), "id-match")
