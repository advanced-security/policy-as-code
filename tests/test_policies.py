import unittest

from ghastoolkit import Repository

from ghascompliance.policies.base import (
    CodeScanningPolicy,
    PolicyV3,
    SecretScanningPolicy,
)
from ghascompliance.policies.severities import SeverityLevelEnum


class TestPolicies(unittest.TestCase):
    def test_default(self):
        policy = PolicyV3()
        self.assertEqual(policy.version, "3")
        self.assertEqual(policy.name, "Policy")
        self.assertFalse(policy.display)

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
