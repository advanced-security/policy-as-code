import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.append(".")

from ghascompliance.policy import Policy, parseDateTime


def campaignEndingIn(days: int, state: str = "open") -> dict:
    ends_at = datetime.now(timezone.utc) + timedelta(days=days)
    return {
        "number": 1,
        "name": "Critical CodeQL Alerts",
        "state": state,
        "created_at": "2024-01-01T00:00:00Z",
        "published_at": "2024-01-01T00:00:00Z",
        "ends_at": ends_at.strftime("%Y-%m-%dT%XZ"),
    }


class TestPolicyCampaigns(unittest.TestCase):
    def setUp(self):
        self.policy = Policy("error")
        return super().setUp()

    def testCampaignsDisabledByDefault(self):
        self.policy.loadPolicy({"name": "test", "codescanning": {"level": "error"}})

        self.assertEqual(self.policy.campaigns, [])

    def testLoadCampaigns(self):
        self.policy.loadPolicy(
            {
                "name": "test",
                "campaigns": [
                    {
                        "name": "Critical CodeQL Alerts",
                        "grace": 7,
                        "codescanning": {"level": "critical"},
                    }
                ],
            }
        )

        self.assertEqual(len(self.policy.campaigns), 1)
        self.assertEqual(self.policy.campaigns[0].get("grace"), 7)
        self.assertEqual(
            self.policy.policy.get("campaigns"),
            self.policy.campaigns,
        )

    def testCampaignRequiresName(self):
        with self.assertRaises(Exception):
            self.policy.loadPolicy(
                {"name": "test", "campaigns": [{"codescanning": {"level": "critical"}}]}
            )

    def testCampaignDisallowedSection(self):
        with self.assertRaises(Exception):
            self.policy.loadPolicy(
                {
                    "name": "test",
                    "campaigns": [{"name": "campaign", "secretscanning": {}}],
                }
            )

    def testCampaignDisallowedBlock(self):
        with self.assertRaises(Exception):
            self.policy.loadPolicy(
                {
                    "name": "test",
                    "campaigns": [
                        {"name": "campaign", "codescanning": {"remediate": {"all": 1}}}
                    ],
                }
            )

    def testCampaignInvalidGrace(self):
        with self.assertRaises(Exception):
            self.policy.loadPolicy(
                {"name": "test", "campaigns": [{"name": "campaign", "grace": -1}]}
            )

    def testCampaignPolicyMatching(self):
        self.policy.loadPolicy(
            {
                "name": "test",
                "campaigns": [
                    {"name": "Critical *", "codescanning": {"level": "critical"}}
                ],
            }
        )

        self.assertEqual(len(self.policy.getCampaignPolicies("Critical Alerts")), 1)
        self.assertEqual(len(self.policy.getCampaignPolicies("SQL Injection")), 0)

    def testCampaignOverdue(self):
        self.assertTrue(self.policy.checkCampaignOverdue(campaignEndingIn(-1)))
        self.assertFalse(self.policy.checkCampaignOverdue(campaignEndingIn(1)))
        # today is not overdue
        self.assertFalse(self.policy.checkCampaignOverdue(campaignEndingIn(0)))

    def testCampaignOverdueGrace(self):
        campaign = campaignEndingIn(-5)

        self.assertTrue(self.policy.checkCampaignOverdue(campaign, 1))
        self.assertFalse(self.policy.checkCampaignOverdue(campaign, 10))

    def testCampaignClosedIsNotOverdue(self):
        self.assertFalse(
            self.policy.checkCampaignOverdue(campaignEndingIn(-1, state="closed"))
        )

    def testCampaignWithoutDueDate(self):
        self.assertFalse(self.policy.checkCampaignOverdue({"name": "campaign"}))

    def testCampaignViolationLevel(self):
        campaign = {"name": "campaign", "codescanning": {"level": "critical"}}

        self.assertTrue(
            self.policy.checkCampaignViolation("critical", "codescanning", campaign)
        )
        self.assertFalse(
            self.policy.checkCampaignViolation("medium", "codescanning", campaign)
        )
        # technology not in the campaign policy
        self.assertFalse(
            self.policy.checkCampaignViolation("critical", "dependabot", campaign)
        )

    def testCampaignViolationConditionsAndIgnores(self):
        campaign = {
            "name": "campaign",
            "codescanning": {
                "level": "none",
                "conditions": {"ids": ["js/sql-injection"]},
                "ignores": {"ids": ["js/unused-local-variable"]},
            },
        }

        self.assertTrue(
            self.policy.checkCampaignViolation(
                "note", "codescanning", campaign, ids=["js/sql-injection"]
            )
        )
        self.assertFalse(
            self.policy.checkCampaignViolation(
                "critical", "codescanning", campaign, ids=["js/unused-local-variable"]
            )
        )

    def testCampaignViolationAlertCreatedAfterCampaign(self):
        campaign = {"name": "campaign", "codescanning": {"level": "critical"}}
        campaign_start = datetime(2024, 1, 1)

        self.assertTrue(
            self.policy.checkCampaignViolation(
                "critical",
                "codescanning",
                campaign,
                creation_time=datetime(2023, 12, 1),
                campaign_start=campaign_start,
            )
        )
        # alert created after the campaign was published is not part of it
        self.assertFalse(
            self.policy.checkCampaignViolation(
                "critical",
                "codescanning",
                campaign,
                creation_time=datetime(2024, 2, 1),
                campaign_start=campaign_start,
            )
        )

    def testParseDateTime(self):
        self.assertEqual(
            parseDateTime("2024-01-01T00:00:00Z"), datetime(2024, 1, 1, 0, 0, 0)
        )
        self.assertEqual(
            parseDateTime("2024-01-01T01:00:00+01:00"), datetime(2024, 1, 1, 0, 0, 0)
        )
        self.assertIsNone(parseDateTime("not-a-date"))
        self.assertIsNone(parseDateTime(None))


if __name__ == "__main__":
    unittest.main()
