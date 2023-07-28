"""SecretScanningChecker."""

from ghastoolkit import SecretScanning, SecretAlert
from ghascompliance.octokit.octokit import Octokit

from ghascompliance.policies.base import SecretScanningPolicy, Policy
from ghascompliance.checks.checker import Checker
from ghascompliance.policies.state import PolicyState


class SecretScanningChecker(Checker):
    """Secret Scanning checker."""

    def __init__(self, name: str, policy: Policy) -> None:
        """Initialise CodeScanningChecker."""
        self.secret_scanning = SecretScanning()
        super().__init__(name, policy)

    def enabled(self) -> bool:
        """Check to see if code scanning is enabled in the policy."""
        if isinstance(self.policy.codescanning, (list)):
            return True  # assume that as list is enabled
        else:
            return self.policy.codescanning.enabled

    def check(self) -> PolicyState:
        """Checks alerts for Secret Scanning against policy."""
        alerts = self.secret_scanning.getAlerts("open")

        for policy in self.policy.secretscanning:
            # check: enabled
            if policy.enabled and not self.secret_scanning.isEnabled():
                self.state.critical(f"Secret Scanning is not enabled")
                return self.state

            if (
                policy.push_protection
                and self.secret_scanning.isPushProtectionEnabled()
            ):
                self.state.error(
                    f"Secret Scanning Push Protection is disabled", "enabled"
                )

            for alert in alerts:
                self.checkSecretScanningAlert(policy, alert)

        return self.state

    def checkSecretScanningAlert(
        self, policy: SecretScanningPolicy, alert: SecretAlert
    ):
        """Check a Secret Scanning alert against policy."""
        return
