"""SecretScanningChecker."""

from typing import List
from ghastoolkit import SecretScanning, SecretAlert
from ghastoolkit.octokit.github import GitHub
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

    def isEnabled(self) -> bool:
        """Is Secret Scanning Policy enabled."""
        return len(self.policy.secretscanning) != 0

    def error(self, alert: SecretAlert, trigger_name: str = "na"):
        """Secret Scanning check error."""
        err = f"Unresolved Secret :: {alert.secret_type}"
        if Octokit.debugging_enabled():
            err += f" ({alert.number})"
        self.state.error(err, trigger_name)

    def warning(self, alert: SecretAlert, trigger_name: str = "na"):
        """Secret Scanning check warning."""
        self.state.warning(f"Unresolved Secret :: {alert.secret_type}", trigger_name)

    def check(self) -> PolicyState:
        """Checks alerts for Secret Scanning against policy."""
        alerts = self.getAlerts()
        Octokit.info("Total Code Scanning Alerts :: " + str(len(alerts)))

        for policy in self.policy.secretscanning:
            # check: enabled
            if policy.enabled and not self.secret_scanning.isEnabled():
                self.state.critical(f"Secret Scanning is not enabled")
                return self.state
            # check: enabled push protection
            if (
                policy.push_protection
                and not self.secret_scanning.isPushProtectionEnabled()
            ):
                self.state.error(
                    f"Secret Scanning Push Protection is disabled", "enabled"
                )
            # check: enabled push protection warning
            elif (
                policy.push_protection_warning
                and not self.secret_scanning.isPushProtectionEnabled()
            ):
                self.state.warning(
                    "Secret Scanning Push Protection is disabled", "enabled-warning"
                )

            for alert in alerts:
                self.checkSecretScanningAlert(policy, alert)

        return self.state

    def getAlerts(self) -> List[SecretAlert]:
        """Get Alerts from GitHub."""
        if GitHub.repository.isInPullRequest():
            Octokit.info("Secret Scanning Alerts from Pull Request (alert diff)")
            pr_base = (
                GitHub.repository.getPullRequestInfo().get("base", {}).get("ref", "")
            )
            alerts = self.secret_scanning.getAlertsInPR()
        else:
            Octokit.debug(
                f"Secret Scanning Alerts from reference :: {GitHub.repository.reference}"
            )
            alerts = self.secret_scanning.getAlerts("open")
        return alerts

    def checkSecretScanningAlert(
        self, policy: SecretScanningPolicy, alert: SecretAlert
    ):
        """Check a Secret Scanning alert against policy."""
        # check: severity
        if policy.severity.value == "all":
            self.error(alert, "severity-all")
            return
        # check: ignore ids
        if self.matchContent(alert.secret_type, policy.ids_ignores):
            self.state.ignore("ignore alert", "id-match")
            return
        # check: warning ids
        if self.matchContent(alert.secret_type, policy.ids_warnings):
            self.warning(alert, "id-match")
            return
        # check: match id
        if self.matchContent(alert.secret_type, policy.ids):
            self.error(alert, "id-match")
            return

        # check: match name
        if self.matchContent(alert.secret_type_display_name, policy.names):
            self.error(alert, "name-match")
            return

        return
