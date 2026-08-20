import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.append(".")

from ghastoolkit import GitHub

from ghascompliance import checks as checks_module
from ghascompliance.checks import Checks
from ghascompliance.policy import Policy


def codeScanningAlert(
    rule_id: str = "js/sql-injection",
    severity: str = "critical",
    created_at: str = "2024-01-01T00:00:00Z",
) -> MagicMock:
    alert = MagicMock()
    alert.severity = severity
    alert.description = "SQL Injection"
    alert.rule_id = rule_id
    alert.get.return_value = created_at
    return alert


class TestChecksCampaigns(unittest.TestCase):
    def setUp(self) -> None:
        GitHub.init(
            "advanced-security/policy-as-code",
            instance="https://github.com",
            retrieve_metadata=False,
        )

        self.campaign = {
            "number": 1,
            "name": "Critical CodeQL Alerts",
            "state": "open",
            "created_at": "2024-02-01T00:00:00Z",
            "published_at": "2024-02-01T00:00:00Z",
            "ends_at": "2024-03-01T00:00:00Z",
        }

        self.policy = Policy("error")
        self.policy.loadPolicy(
            {
                "name": "test",
                "campaigns": [
                    {"name": "Critical *", "codescanning": {"level": "critical"}}
                ],
            }
        )
        self.checks = Checks(self.policy, results_path=".compliance")

        return super().setUp()

    def runChecks(self, campaigns: list, alerts: list) -> int:
        with patch.object(
            Checks, "getSecurityCampaigns", return_value=campaigns
        ), patch.object(checks_module, "CodeScanning") as codescanning:
            codescanning.return_value.getAlerts.return_value = alerts
            return self.checks.checkCampaigns()

    def testCampaignsDisabled(self):
        self.policy.campaigns = []

        self.assertEqual(self.runChecks([self.campaign], [codeScanningAlert()]), 0)

    def testOverdueCampaignViolation(self):
        self.assertEqual(self.runChecks([self.campaign], [codeScanningAlert()]), 1)

    def testCampaignNotOverdue(self):
        self.campaign["ends_at"] = "2999-03-01T00:00:00Z"

        self.assertEqual(self.runChecks([self.campaign], [codeScanningAlert()]), 0)

    def testAlertCreatedAfterCampaign(self):
        alert = codeScanningAlert(created_at="2024-02-02T00:00:00Z")

        self.assertEqual(self.runChecks([self.campaign], [alert]), 0)

    def testAlertBelowCampaignLevel(self):
        alert = codeScanningAlert(severity="medium")

        self.assertEqual(self.runChecks([self.campaign], [alert]), 0)

    def testCampaignNotInOrganization(self):
        self.campaign["name"] = "Some other campaign"

        self.assertEqual(self.runChecks([self.campaign], [codeScanningAlert()]), 0)


if __name__ == "__main__":
    unittest.main()
