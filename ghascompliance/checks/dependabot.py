"""DependabotChecker."""
from typing import List

from ghastoolkit import Dependabot, DependencyGraph, DependencyAlert

from ghascompliance.policies.base import SupplyChainPolicy, Policy
from ghascompliance.checks.checker import Checker
from ghascompliance.octokit.octokit import Octokit
from ghascompliance.policies.severities import SeverityLevelEnum


class DependabotChecker(Checker):
    """Supply Chain checker."""

    def __init__(self, name: str, policy: Policy) -> None:
        """Initialise DependabotChecker."""
        self.dependabot = Dependabot()

        super().__init__(name, policy)

    def isEnabled(self) -> bool:
        return len(self.policy.supplychain) != 0

    def error(self, alert: DependencyAlert, check_name: str = "na"):
        """Log a Supply Chain error."""
        err = f"{alert.purl}"
        self.state.error(err, check_name)

    def warning(self, alert: DependencyAlert, trigger_name: str = "na"):
        """Secret Scanning check warning."""
        self.state.warning(
            f"{alert.advisory} - {alert.purl} - {alert.severity}", trigger_name
        )

    def check(self):
        """Check Supply Chain alerts."""
        alerts = self.getAlerts()

        Octokit.info("Total Supply Chain Alerts :: " + str(len(alerts)))
        Octokit.debug(f"Total Supply Chain Policies :: {len(self.policy.supplychain)}")

        for policy in self.policy.supplychain:
            # check: enabled
            if policy.enabled and not self.dependabot.isEnabled():
                self.state.critical("Dependabot is not enabled")
                return

            if (
                policy.security_updates
                and not self.dependabot.isSecurityUpdatesEnabled()
            ):
                self.state.error("Dependabot Security Updates is not enabled")

            # severities
            self.severities = SeverityLevelEnum.getSeveritiesFromName(
                policy.severity.value
            )

            for alert in alerts:
                self.checkSupplyChainAlert(policy, alert)

    def getAlerts(self) -> List[DependencyAlert]:
        """Get Alerts."""
        return self.dependabot.getAlerts()

    def checkSupplyChainAlert(self, policy: SupplyChainPolicy, alert: DependencyAlert):
        """Check Supply Chain / Dependabot alerts."""
        # check: severity
        if alert.severity in self.severities:
            self.error(alert, "severity")
            return
