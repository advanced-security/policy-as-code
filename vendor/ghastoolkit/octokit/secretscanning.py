import logging
from dataclasses import dataclass, field
from typing import Optional

from ghastoolkit.octokit.github import GitHub, Repository
from ghastoolkit.octokit.octokit import OctoItem, RestRequest, loadOctoItem


logger = logging.getLogger("ghastoolkit.octokit.secretscanning")


@dataclass
class SecretAlert(OctoItem):
    """Secret Scanning Alert."""

    number: int
    """Number / Identifier"""
    state: str
    """Alert State"""

    created_at: str
    """Created Timestamp"""

    secret_type: str
    """Secret Scanning type"""
    secret_type_display_name: str
    """Secret Scanning type display name"""
    secret: str
    """Secret value (sensitive)"""

    _locations: list[dict] = field(default_factory=list)
    _sha: Optional[str] = None

    @property
    def locations(self) -> list[dict]:
        """Get Alert locations. Uses a cached version or request from API."""
        if not self._locations:
            self._locations = SecretScanning().getAlertLocations(self.number)
        return self._locations

    @property
    def commit_sha(self) -> Optional[str]:
        """Get commit sha if present."""
        if self._sha is None:
            for loc in self.locations:
                if loc.get("type") == "commit":
                    self._sha = loc.get("details", {}).get("blob_sha")
                    break
        return self._sha

    def __str__(self) -> str:
        return f"SecretAlert({self.number}, '{self.secret_type}')"


class SecretScanning:
    """Secret Scanning API."""

    def __init__(self, repository: Optional[Repository] = None) -> None:
        """Initialise Secret Scanning API."""
        self.repository = repository or GitHub.repository
        if not self.repository:
            raise Exception("SecretScanning requires Repository to be set")

        self.rest = RestRequest(self.repository)

        self.state = None

    def isEnabled(self) -> bool:
        """Check to see if Secret Scanning is enabled or not via the repository status.

        https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#get-a-repository
        """
        if not self.state:
            self.state = self.getStatus()
        if self.state.get("visibility") == "public":
            logger.debug("All public repositories have secret scanning enabled")
            return True
        return (
            self.state.get("security_and_analysis", {})
            .get("secret_scanning", {})
            .get("status", "disabled")
            == "enabled"
        )

    def isPushProtectionEnabled(self) -> bool:
        """Check if Push Protection is enabled."""
        if not self.state:
            self.state = self.getStatus()

        status = (
            self.state.get("security_and_analysis", {})
            .get("secret_scanning_push_protection", {})
            .get("status", "disabled")
        )
        return status == "enabled"

    def getStatus(self) -> dict:
        """Get Status of GitHub Advanced Security."""
        result = self.rest.get("/repos/{owner}/{repo}")
        if isinstance(result, dict):
            return result
        raise Exception("Failed to get the current state of secret scanning")

    def getOrganizationAlerts(self, state: Optional[str] = None) -> list[dict]:
        """Get Organization Alerts.

        https://docs.github.com/en/rest/secret-scanning#list-secret-scanning-alerts-for-an-organization
        """
        results = self.rest.get("/orgs/{org}/secret-scanning/alerts", {"state": state})
        if isinstance(results, list):
            return results
        raise Exception(f"Error getting organization secret scanning results")

    @RestRequest.restGet("/repos/{owner}/{repo}/secret-scanning/alerts")
    def getAlerts(self, state: str = "open") -> list[SecretAlert]:
        """Get Repository alerts.

        https://docs.github.com/en/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository
        """
        return []

    def getAlert(
        self, alert_number: int, state: Optional[str] = None
    ) -> Optional[SecretAlert]:
        """Get Alert by `alert_number`.

        https://docs.github.com/en/rest/secret-scanning#get-a-secret-scanning-alert
        """
        results = self.rest.get(
            "/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}",
            {"alert_number": alert_number, "state": state},
        )
        if isinstance(results, dict):
            return loadOctoItem(SecretAlert, results)

    def getAlertsInPR(self) -> list[SecretAlert]:
        """Get Alerts in a Pull Request."""
        results = []
        pr_commits = self.repository.getPullRequestCommits()
        logger.debug(f"Number of Commits in PR :: {len(pr_commits)}")

        for alert in self.getAlerts("open"):
            if alert.commit_sha in pr_commits:
                results.append(alert)

        return results

    def getAlertLocations(self, alert_number: int) -> list[dict]:
        """Get Alert Locations by `alert_number`.

        https://docs.github.com/en/rest/secret-scanning#list-locations-for-a-secret-scanning-alert
        """
        results = self.rest.get(
            "/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations",
            {"alert_number": alert_number},
        )
        if isinstance(results, list):
            return results
        raise Exception(f"Error getting alert locations")
