from dataclasses import dataclass
import json
import logging
from typing import Any, Optional
from ghastoolkit.octokit.github import GitHub, Repository
from ghastoolkit.octokit.octokit import OctoItem, RestRequest

logger = logging.getLogger("ghastoolkit.octokit.codescanning")


@dataclass
class CodeAlert(OctoItem):
    number: int
    state: str

    created_at: str

    rule: dict
    tool: dict

    _instances: Optional[list[dict]] = None

    @property
    def rule_id(self):
        return self.rule.get("id")

    @property
    def description(self):
        return self.rule.get("description")

    @property
    def tool_name(self):
        return self.tool.get("name")

    @property
    def tool_fullname(self):
        version = self.tool.get("version")
        return f"{self.tool_name}@{version}"

    @property
    def severity(self):
        return self.rule.get("severity")

    @property
    def instances(self) -> list[dict]:
        if not self._instances:
            self._instances = CodeScanning().getAlertInstances(self.number)
        return self._instances

    def __str__(self) -> str:
        return f"CodeAlert({self.number}, '{self.state}', '{self.tool_name}', '{self.rule_id}')"


class CodeScanning:
    def __init__(self, repository: Optional[Repository] = None) -> None:
        """GitHub Code Scanning REST API

        https://docs.github.com/en/rest/code-scanning
        """
        self.repository = repository or GitHub.repository
        if not self.repository:
            raise Exception("CodeScanning requires Repository to be set")
        self.rest = RestRequest(self.repository)

    def getOrganizationAlerts(self, state: str = "open") -> list[dict[Any, Any]]:
        """Get Organization Alerts

        https://docs.github.com/en/rest/code-scanning#list-code-scanning-alerts-for-an-organization
        """
        results = self.rest.get(
            "/orgs/{org}/code-scanning/alerts", {"state": state}, authenticated=True
        )
        if isinstance(results, list):
            return results
        raise Exception(f"Error getting alerts from Organization")

    @RestRequest.restGet(
        "/repos/{owner}/{repo}/code-scanning/alerts", authenticated=True
    )
    def getAlerts(
        self,
        state: str = "open",
        tool_name: Optional[str] = None,
        ref: Optional[str] = None,
    ) -> list[CodeAlert]:
        """Get all code scanning alerts
        https://docs.github.com/en/rest/code-scanning#list-code-scanning-alerts-for-a-repository
        """
        return []

    def getAlertsInPR(self, base: str) -> list[dict]:
        """Get the open alerts in a Pull Request (delta / diff).

        Note this operation is slow due to it needing to lookup each alert instance
        information.

        base: str - Base reference
        https://docs.github.com/en/rest/code-scanning#list-instances-of-a-code-scanning-alert
        """
        if not self.repository.reference or not self.repository.isInPullRequest():
            return []

        results = []
        alerts = self.getAlerts("open", ref=self.repository.reference)

        for alert in alerts:
            number = alert.get("number")
            alert_info = self.getAlertInstances(number, ref=base)
            if len(alert_info) == 0:
                results.append(alert)
        return results

    @RestRequest.restGet(
        "/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}", authenticated=True
    )
    def getAlert(self, alert_number: int) -> dict:
        """Get Single Alert
        https://docs.github.com/en/rest/code-scanning#get-a-code-scanning-alert
        """
        return {}

    def getAlertInstances(
        self, alert_number: int, ref: Optional[str] = None
    ) -> list[dict]:
        result = self.rest.get(
            "/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
            {"alert_number": alert_number, "ref": ref},
        )
        return result

    def getAnalyses(
        self, reference: Optional[str] = None, tool: Optional[str] = None
    ) -> list[dict]:
        """Get a list of analyses for a repository
        https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning#list-code-scanning-analyses-for-a-repository
        """
        results = self.rest.get(
            "/repos/{org}/{repo}/code-scanning/analyses",
            {"tool_name": tool, "ref": reference or self.repository.reference},
        )
        if isinstance(results, list):
            return results
        raise Exception(f"")

    def getLatestAnalyses(
        self, reference: Optional[str] = None, tool: Optional[str] = None
    ) -> list[dict]:
        """Get Latest Analyses for every tool"""
        tools = set()
        results = []
        for analysis in self.getAnalyses(reference, tool):
            name = analysis.get("tool", {}).get("name")
            if name in tools:
                continue
            tools.add(name)
            results.append(analysis)

        return results

    def getSarifId(self, url: str) -> int:
        """Get the latest SARIF ID from a URL"""
        if url and "/" in url:
            return int(url.split("/")[-1])
        return -1

    def downloadSARIF(self, output: str, sarif_id: int) -> bool:
        """Get SARIF by ID (UUID)"""
        logger.debug(f"Downloading SARIF file :: {sarif_id}")

        # need to change "Accept" and then reset
        og_accept = self.rest.session.headers.pop("Accept")
        self.rest.session.headers["Accept"] = "application/sarif+json"
        result = self.rest.get(
            "/repos/{org}/{repo}/code-scanning/analyses/{sarif_id}",
            {"sarif_id": sarif_id},
        )
        self.rest.session.headers["Accept"] = og_accept

        logger.debug(f"Saving SARIF file to :: {output}")
        with open(output, "w") as handle:
            json.dump(result, handle, indent=2)
        logger.debug("Saved SARIF file")
        return True

    # CodeQL

    def getCodeQLDatabases(self) -> list[dict]:
        """List CodeQL databases for a repository

        https://docs.github.com/en/rest/code-scanning?apiVersion=2022-11-28#list-codeql-databases-for-a-repository
        """
        return self.rest.get("/repos/{owner}/{repo}/code-scanning/codeql/databases")

    def getCodeQLDatabase(self, language: str) -> dict:
        """Get a CodeQL database for a repository
        https://docs.github.com/en/rest/code-scanning?apiVersion=2022-11-28#get-a-codeql-database-for-a-repository
        """
        return self.rest.get(
            "/repos/{owner}/{repo}/code-scanning/codeql/databases/{language}",
            {"language": language},
        )
