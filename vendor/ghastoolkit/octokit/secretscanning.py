from os import stat
from typing import Optional

from ghastoolkit.octokit.github import GitHub, Repository
from ghastoolkit.octokit.octokit import RestRequest


class SecretScanning:
    def __init__(self, repository: Optional[Repository] = None) -> None:
        self.repository = repository or GitHub.repository
        if not self.repository:
            raise Exception("SecretScanning requires Repository to be set")

        self.rest = RestRequest(self.repository)

    def getOrganizationAlerts(self, state: Optional[str] = None) -> list[dict]:
        """Get Organization Alerts

        https://docs.github.com/en/rest/secret-scanning#list-secret-scanning-alerts-for-an-organization
        """
        results = self.rest.get("/orgs/{org}/secret-scanning/alerts", {"state": state})
        if isinstance(results, list):
            return results
        raise Exception(f"Error getting organization secret scanning results")

    def getAlerts(self, state: Optional[str] = None) -> list[dict]:
        """Get Repository alerts

        https://docs.github.com/en/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository
        """
        results = self.rest.get(
            "/repos/{owner}/{repo}/secret-scanning/alerts", {"state": state}
        )
        if isinstance(results, list):
            return results
        raise Exception(f"Error getting repository secret scanning results")

    def getAlert(self, alert_number: int, state: Optional[str] = None) -> dict:
        """Get Alert by `alert_number`

        https://docs.github.com/en/rest/secret-scanning#get-a-secret-scanning-alert
        """
        results = self.rest.get(
            "/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}",
            {"alert_number": alert_number, "state": state},
        )
        if isinstance(results, dict):
            return results
        raise Exception(f"Error getting repository secret scanning result")

    def getAlertLocations(self, alert_number: int) -> list[dict]:
        """Get Alert Locations by `alert_number`

        https://docs.github.com/en/rest/secret-scanning#list-locations-for-a-secret-scanning-alert
        """
        results = self.rest.get(
            "/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations",
            {"alert_number": alert_number},
        )
        if isinstance(results, list):
            return results
        raise Exception(f"Error getting alert locations")
