import unittest

from ghastoolkit import CodeAlert, SecretAlert
from ghascompliance.policies.base import PolicyV3
from ghascompliance.policies.severities import SeverityLevelEnum


def createAlert(secret_type="aws") -> SecretAlert:
    """Create an alert helper."""
    return SecretAlert(
        0,
        "open",
        "2020-11-06T18:48:51Z",
        secret_type=secret_type,
        secret_type_display_name="AWS",
        secret="my_key",
    )


class TestCodeScanningChecker(unittest.TestCase):
    def setUp(self) -> None:
        self.root_policy = PolicyV3()
        self.policy = self.root_policy.secretscanning[0]

        from ghascompliance.checks.secretscanning import SecretScanningChecker

        self.checker = SecretScanningChecker("Secret Scanning", self.policy)
        return super().setUp()

    def test_check_ids(self):
        """Check ID matches."""
        self.policy.ids = ["aws"]

        self.checker.checkSecretScanningAlert(self.policy, createAlert())
        self.assertEqual(len(self.checker.state.errors), 1)
        error = self.checker.state.errors.pop(0)
        self.assertEqual(error.get("trigger"), "id-match")

        self.checker.state.reset()

        self.checker.checkSecretScanningAlert(
            self.policy, createAlert(secret_type="azure")
        )
        self.assertEqual(len(self.checker.state.errors), 0)

    def test_check_ids_ignore(self):
        self.policy.ids_ignores = ["aws"]

        self.checker.checkSecretScanningAlert(self.policy, createAlert())
        self.assertEqual(len(self.checker.state.ignored), 1)
        ignore = self.checker.state.ignored.pop(0)
        self.assertEqual(ignore.get("trigger"), "id-match")

    def test_check_ids_warning(self):
        self.policy.ids_warnings = ["aws"]

        self.checker.checkSecretScanningAlert(self.policy, createAlert())
        self.assertEqual(len(self.checker.state.warnings), 1)
        result = self.checker.state.warnings.pop(0)
        self.assertEqual(result.get("trigger"), "id-match")
