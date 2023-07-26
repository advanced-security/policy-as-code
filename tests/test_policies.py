from sre_compile import dis
import unittest

from ghastoolkit import Repository

from ghascompliance.policies.base import (
    CodeScanningPolicy,
    Display,
    PolicyV3,
    Policy,
    SecretScanningPolicy,
)
from ghascompliance.policies.severities import SeverityLevelEnum


class TestPolicies(unittest.TestCase):
    def test_default(self):
        policy = PolicyV3()
        self.assertEqual(policy.version, "3")
        self.assertEqual(policy.name, "Policy")
        self.assertFalse(policy.display.detailed)

        if isinstance(policy.codescanning, CodeScanningPolicy):
            self.assertTrue(policy.codescanning.enabled)
            self.assertEqual(policy.codescanning.severity, SeverityLevelEnum.ERROR)

        self.assertTrue(policy.supplychain.enabled)
        self.assertEqual(policy.supplychain.severity, SeverityLevelEnum.HIGH)

        self.assertTrue(policy.secretscanning.enabled)
        self.assertEqual(policy.secretscanning.severity, SeverityLevelEnum.ALL)

    def test_get_policy_default(self):
        policy = PolicyV3(
            codescanning=CodeScanningPolicy(False, name="MyCS"),
            secretscanning=SecretScanningPolicy(severity=SeverityLevelEnum.LOW),
        )

        r = Repository.parseRepository("rand/repo")
        p = policy.getPolicy(r)
        self.assertEqual(p.codescanning.name, "MyCS")
        self.assertEqual(p.secretscanning.severity, SeverityLevelEnum.LOW)

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
