import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from ghastoolkit.errors import (
    GHASToolkitAuthenticationError,
    GHASToolkitError,
    GHASToolkitTypeError,
)
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

    secret_type: str
    """Secret Scanning type"""
    secret_type_display_name: str
    """Secret Scanning type display name"""
    secret: str
    """Secret value (sensitive)"""

    created_at: str
    """Created Timestamp"""
    resolved_at: Optional[str] = None
    """Resolved Timestamp"""
    resolved_by: Optional[dict[str, Any]] = None
    """Resolved By"""

    push_protection_bypassed: bool = False
    """Push Protection Bypassed"""
    push_protection_bypassed_by: Optional[dict[str, Any]] = None
    """Push Protection Bypassed By"""
    push_protection_bypassed_at: Optional[str] = None
    """Push Protection Bypassed At"""

    resolution_comment: Optional[str] = None
    """Resolution Comment"""

    validity: str = "unknown"
    """Validity of secret"""

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

    @property
    def mttr(self) -> Optional[timedelta]:
        """Calculate Mean Time To Resolution / Remidiate (MTTR) for a closed/fixed alert."""
        if self.created_at and self.resolved_at:
            # GitHub returns ISO 8601 timestamps with a Z at the end
            # datetime.fromisoformat() doesn't like the Z
            created = self.created_at.replace("Z", "+00:00")
            resolved = self.resolved_at.replace("Z", "+00:00")
            return datetime.fromisoformat(resolved) - datetime.fromisoformat(created)
        return None

    def __str__(self) -> str:
        return f"SecretAlert({self.number}, '{self.secret_type}')"


class SecretScanning:
    """Secret Scanning API."""

    def __init__(self, repository: Optional[Repository] = None) -> None:
        """Initialise Secret Scanning API."""
        self.repository = repository or GitHub.repository
        if not self.repository:
            raise GHASToolkitError("SecretScanning requires Repository to be set")

        self.rest = RestRequest(self.repository)

        self.state = None

    def isEnabled(self) -> bool:
        """Check to see if Secret Scanning is enabled or not via the repository status.

        Permissions:
        - "Administration" repository permissions (read)

        https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#get-a-repository
        """
        if not self.state:
            self.state = self.getStatus()

        if self.state.get("visibility") == "public":
            logger.debug("All public repositories have secret scanning enabled")
            return True
        if saa := self.state.get("security_and_analysis"):
            return saa.get("secret_scanning", {}).get("status", "disabled") == "enabled"

        raise GHASToolkitAuthenticationError(
            "Failed to fetch Secret Scanning repository settings",
            docs="https://docs.github.com/en/enterprise-cloud@latest/rest/repos/repos#get-a-repository",
            permissions=["Repository Administration (read)"],
        )

    def isPushProtectionEnabled(self) -> bool:
        """Check if Push Protection is enabled.

        Permissions:
        - "Administration" repository permissions (read)

        https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#get-a-repository
        """
        if not self.state:
            self.state = self.getStatus()

        if ssa := self.state.get("security_and_analysis"):
            return (
                ssa.get("secret_scanning_push_protection", {}).get("status", "disabled")
                == "enabled"
            )

        raise GHASToolkitAuthenticationError(
            "Failed to get Push Protection status",
            permissions=["Repository Administration (read)"],
            docs="https://docs.github.com/en/rest/repos/repos#get-a-repository",
        )

    def getStatus(self) -> dict:
        """Get Status of GitHub Advanced Security."""
        result = self.rest.get("/repos/{owner}/{repo}")
        if isinstance(result, dict):
            return result
        raise GHASToolkitTypeError(
            "Failed to get the current state of secret scanning",
            permissions=["Repository Administration (read)"],
            docs="https://docs.github.com/en/rest/repos/repos#get-a-repository",
        )

    def getOrganizationAlerts(self, state: Optional[str] = None) -> list[dict]:
        """Get Organization Alerts.

        Permissions:
        - "Secret scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/secret-scanning#list-secret-scanning-alerts-for-an-organization
        """
        results = self.rest.get("/orgs/{org}/secret-scanning/alerts", {"state": state})
        if isinstance(results, list):
            return results

        raise GHASToolkitTypeError(
            f"Error getting organization secret scanning results",
            permissions=["Secret scanning alerts (read)"],
            docs="https://docs.github.com/en/rest/secret-scanning#list-secret-scanning-alerts-for-an-organization",
        )

    def getAlerts(self, state: str = "open") -> list[SecretAlert]:
        """Get Repository alerts.

        Permissions:
        - "Secret scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository
        """

        results = self.rest.get(
            "/repos/{owner}/{repo}/secret-scanning/alerts", {"state": state}
        )
        if isinstance(results, list):
            return [loadOctoItem(SecretAlert, item) for item in results]

        raise GHASToolkitTypeError(
            "Error getting secret scanning alerts",
            docs="https://docs.github.com/en/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository",
        )

    def getAlert(
        self, alert_number: int, state: Optional[str] = None
    ) -> Optional[SecretAlert]:
        """Get Alert by `alert_number`.

        Permissions:
        - "Secret scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/secret-scanning#get-a-secret-scanning-alert
        """
        results = self.rest.get(
            "/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}",
            {"alert_number": alert_number, "state": state},
        )
        if isinstance(results, dict):
            return loadOctoItem(SecretAlert, results)
        raise GHASToolkitTypeError(
            "Error getting secret scanning alert",
            docs="https://docs.github.com/en/rest/secret-scanning#get-a-secret-scanning-alert",
        )

    def getAlertsInPR(self) -> list[SecretAlert]:
        """Get Alerts in a Pull Request.

        Permissions:
        - "Secret scanning alerts" repository permissions (read)
        - "Pull requests" repository permissions (read)
        """
        results = []
        pr_commits = self.repository.getPullRequestCommits()
        logger.debug(f"Number of Commits in PR :: {len(pr_commits)}")

        for alert in self.getAlerts("open"):
            if alert.commit_sha in pr_commits:
                results.append(alert)

        return results

    def getAlertLocations(self, alert_number: int) -> list[dict]:
        """Get Alert Locations by `alert_number`.

        Permissions:
        - "Secret scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/secret-scanning#list-locations-for-a-secret-scanning-alert
        """
        results = self.rest.get(
            "/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations",
            {"alert_number": alert_number},
        )
        if isinstance(results, list):
            return results
        raise GHASToolkitTypeError(
            f"Error getting alert locations",
            docs="https://docs.github.com/en/rest/secret-scanning#list-locations-for-a-secret-scanning-alert",
        )
