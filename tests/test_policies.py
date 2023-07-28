import unittest

from ghastoolkit import Repository

from ghascompliance.policies.base import (
    CodeScanningPolicy,
    Display,
    PolicyV3,
    Policy,
    SecretScanningPolicy,
    loadDict,
)
from ghascompliance.policies.severities import SeverityLevelEnum


class TestPolicies(unittest.TestCase):
    def test_default(self):
        policy = PolicyV3()
        self.assertEqual(policy.version, "3")
        self.assertEqual(policy.name, "Policy")
        self.assertFalse(policy.display.detailed)

        # by default, 1 default policy should be in the list
        self.assertTrue(isinstance(policy.codescanning, list))
        self.assertEqual(len(policy.codescanning), 1)

        self.assertTrue(isinstance(policy.secretscanning, list))
        self.assertEqual(len(policy.secretscanning), 1)

        self.assertTrue(isinstance(policy.supplychain, list))
        self.assertEqual(len(policy.supplychain), 1)

    def test_get_policy_default(self):
        policy = PolicyV3(
            codescanning=[CodeScanningPolicy(False, name="MyCS")],
            secretscanning=[SecretScanningPolicy(severity=SeverityLevelEnum.LOW)],
        )

        r = Repository.parseRepository("rand/repo")
        p = policy.getPolicy(r)

        cs = p.codescanning[0]
        self.assertEqual(cs.name, "MyCS")

        ss = p.secretscanning[0]
        self.assertEqual(ss.severity, SeverityLevelEnum.LOW)

    def test_load_dict(self):
        data = {"enabled": True, "ids": ["test"]}
        result = loadDict(CodeScanningPolicy, data)
        self.assertTrue(result, CodeScanningPolicy)
        self.assertEqual(result.enabled, True)
        self.assertEqual(result.ids, ["test"])

    def test_display(self):
        display = Display.load(True)
        self.assertTrue(display.detailed)
        self.assertTrue(display.pr_summary)

        display = Display.load({"detailed": True, "pr-summary": False})
        self.assertTrue(display.detailed)
        self.assertFalse(display.pr_summary)

    def test_load_display_bool(self):
        policy = Policy(display=True)
        self.assertTrue(isinstance(policy.display, Display))
        self.assertTrue(policy.display.detailed)
