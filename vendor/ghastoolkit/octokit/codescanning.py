"""GitHub Code Scanning API Module."""
from dataclasses import dataclass
import json
import logging
from typing import Any, List, Optional
from ghastoolkit.octokit.github import GitHub, Repository
from ghastoolkit.octokit.octokit import OctoItem, RestRequest, loadOctoItem

logger = logging.getLogger("ghastoolkit.octokit.codescanning")


@dataclass
class CodeAlert(OctoItem):
    """Code Alert from Code Scanning API."""

    number: int
    """Unique Identifier"""
    state: str
    """State of the alert. States can be `open`, `closed`, `dismissed`, or `fixed`."""

    created_at: str
    """Alert Creation date and time."""

    rule: dict
    """Rule Data (rule_id, severity, description, etc)."""
    tool: dict
    """Tool information (name, version, guid)."""

    _instances: Optional[list[dict]] = None

    @property
    def rule_id(self) -> str:
        """Rule Identifier."""
        return self.rule.get("id", "NA")

    @property
    def description(self) -> Optional[str]:
        """Rule Description / Title."""
        return self.rule.get("description")

    @property
    def tool_name(self) -> str:
        """Tool name."""
        return self.tool.get("name", "NA")

    @property
    def tool_fullname(self) -> str:
        """Full tool name with version information."""
        version = self.tool.get("version")
        return f"{self.tool_name}@{version}"

    @property
    def severity(self) -> str:
        """Severity of the alert using `security_severity_level`."""
        return self.rule.get("security_severity_level", "NA")

    @property
    def instances(self) -> list[dict]:
        """Get list of instances of the alert."""
        if not self._instances:
            self._instances = CodeScanning().getAlertInstances(self.number)
        return self._instances

    def __str__(self) -> str:
        """To String."""
        return f"CodeAlert({self.number}, '{self.state}', '{self.tool_name}', '{self.rule_id}')"


class CodeScanning:
    """Code Scanning."""

    def __init__(self, repository: Optional[Repository] = None) -> None:
        """Code Scanning REST API.

        https://docs.github.com/en/rest/code-scanning
        """
        self.repository = repository or GitHub.repository
        self.tools: List[str] = []

        if not self.repository:
            raise Exception("CodeScanning requires Repository to be set")
        self.rest = RestRequest(self.repository)

    def isEnabled(self) -> bool:
        """Check to see if Code Scanning is enabled or not on a repository level."""
        try:
            self.rest.get(
                "/repos/{org}/{repo}/code-scanning/analyses",
                {"ref": self.repository.reference},
                display_error=False,
            )
            return True
        except:
            logger.debug(f"Failed to get analyses...")
        return False

    def enableDefaultSetup(
        self,
        state: str = "configured",
        query_suite: str = "default",
        languages: list[str] = [],
    ) -> dict[str, Any]:
        """Enable Code Scanning using Default Setup using CodeQL."""
        data = {"state": state, "query_suite": query_suite, "languages": languages}
        result = self.rest.patchJson(
            "/repos/{owner}/{repo}/code-scanning/default-setup",
            data,
            expected=[200, 202],
        )
        return result

    def getOrganizationAlerts(self, state: str = "open") -> list[CodeAlert]:
        """Get list of Organization Alerts.

        https://docs.github.com/en/rest/code-scanning#list-code-scanning-alerts-for-an-organization
        """
        results = self.rest.get(
            "/orgs/{org}/code-scanning/alerts", {"state": state}, authenticated=True
        )
        if isinstance(results, list):
            return [loadOctoItem(CodeAlert, alert) for alert in results]
        raise Exception(f"Error getting alerts from Organization")

    def getAlerts(
        self,
        state: str = "open",
        tool_name: Optional[str] = None,
        ref: Optional[str] = None,
        sort: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> list[CodeAlert]:
        """Get all code scanning alerts.

        https://docs.github.com/en/rest/code-scanning#list-code-scanning-alerts-for-a-repository
        """
        results = self.rest.get(
            "/repos/{owner}/{repo}/code-scanning/alerts",
            {
                "state": state,
                "tool_name": tool_name,
                "ref": ref,
                "sort": sort,
                "severity": severity,
            },
            authenticated=True,
        )
        if isinstance(results, list):
            return [loadOctoItem(CodeAlert, alert) for alert in results]
        raise Exception(f"Error getting alerts from Repository")

    def getAlertsInPR(self, base: str) -> list[CodeAlert]:
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

    def getAlert(self, alert_number: int) -> CodeAlert:
        """Get Single Alert information from Code Scanning.

        https://docs.github.com/en/rest/code-scanning#get-a-code-scanning-alert
        """
        result = self.rest.get(
            "/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}",
            {"alert_number": alert_number},
        )
        if isinstance(result, dict):
            return loadOctoItem(CodeAlert, result)
        raise Exception(f"Error getting alert from Repository")

    def getAlertInstances(
        self, alert_number: int, ref: Optional[str] = None
    ) -> list[dict]:
        """Get a list of alert instances."""
        result = self.rest.get(
            "/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
            {"alert_number": alert_number, "ref": ref},
        )
        return result

    def getAnalyses(
        self, reference: Optional[str] = None, tool: Optional[str] = None
    ) -> list[dict]:
        """Get a list of all the analyses for a given repository.

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
        """Get Latest Analyses for every tool."""
        tools = set()
        results = []
        for analysis in self.getAnalyses(reference, tool):
            name = analysis.get("tool", {}).get("name")
            if name in tools:
                continue
            tools.add(name)
            results.append(analysis)

        self.tools = list(tools)

        return results

    def getTools(self, reference: Optional[str] = None) -> List[str]:
        """Get list of tools from the latest analyses."""
        if len(self.tools) == 0:
            self.getLatestAnalyses(reference)
        return self.tools

    def getSarifId(self, url: str) -> int:
        """Get the latest SARIF ID from a URL."""
        if url and "/" in url:
            return int(url.split("/")[-1])
        return -1

    def downloadSARIF(self, output: str, sarif_id: int) -> bool:
        """Get SARIF by ID (UUID)."""
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
        """List CodeQL databases for a repository.

        https://docs.github.com/en/rest/code-scanning?apiVersion=2022-11-28#list-codeql-databases-for-a-repository
        """
        return self.rest.get("/repos/{owner}/{repo}/code-scanning/codeql/databases")

    def getCodeQLDatabase(self, language: str) -> dict:
        """Get a CodeQL database for a repository.

        https://docs.github.com/en/rest/code-scanning?apiVersion=2022-11-28#get-a-codeql-database-for-a-repository
        """
        return self.rest.get(
            "/repos/{owner}/{repo}/code-scanning/codeql/databases/{language}",
            {"language": language},
        )

    def getPacks(self, visibility: str = "internal") -> List[dict]:
        """Get all CodeQL Packs from remote GitHub instance.

        CodeQL Packs are stored in GitHub's container registry so this function might
        return other container images.
        """
        result = self.rest.get(
            "/orgs/{org}/packages",
            {"package_type": "container", "visibility": visibility},
        )
        if isinstance(result, list):
            return result
        return []

    def getPackVersions(self, pack_name: str) -> list[dict]:
        """Get a list of all remote pack versions."""
        if "/" in pack_name:
            # full name
            org, pack_name = pack_name.split("/")
        else:
            org = self.repository.owner

        result = self.rest.get(
            "/orgs/{pack_org}/packages/{package_type}/{package_name}/versions",
            {"pack_org": org, "package_type": "container", "package_name": pack_name},
        )
        if isinstance(result, list):
            return result
        return []

    def getLatestPackVersion(self, pack_name: str) -> dict:
        """Get the current remote CodeQL pack version."""
        versions = self.getPackVersions(pack_name)
        if len(versions) != 0:
            return versions[0]
        return {}

    def downloadExtractorPack(self, repository_name: str, output: str) -> Optional[str]:
        """Download Extractor Packs from GitHub Releases."""
        owner, repo = repository_name.split("/", 1)

        latest_release = self.rest.get(
            f"/repos/{owner}/{repo}/releases/latest",
        )
        if not isinstance(latest_release, dict):
            return
        version = latest_release.get("tag_name", "0.0.0")
        logger.debug(f"Latest Releases :: {version}")

        # for asset in latest_release.get("assets", []):
