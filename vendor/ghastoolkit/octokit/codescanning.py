"""GitHub Code Scanning API Module."""

from dataclasses import dataclass
import json
import time
import logging
from typing import Any, List, Optional, Union
from ghastoolkit.errors import GHASToolkitError, GHASToolkitTypeError
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


@dataclass
class CodeScanningTool(OctoItem):
    """Code Scanning Tool.

    https://docs.github.com/rest/code-scanning/code-scanning#list-code-scanning-analyses-for-a-repository
    """

    name: str
    """Tool Name"""
    guid: Optional[str] = None
    """Tool GUID"""
    version: Optional[str] = None
    """Tool Version"""

    def __str__(self) -> str:
        """To String."""
        if self.version:
            return f"CodeScanningTool({self.name}, '{self.version}')"
        else:
            return f"CodeScanningTool({self.name})"

    def __repr__(self) -> str:
        return self.__str__()


@dataclass
class CodeScanningAnalysisEnvironment(OctoItem):
    """Code Scanning Analysis Environment.

    https://docs.github.com/rest/code-scanning/code-scanning
    """

    language: Optional[str] = None
    """Language"""

    build_mode: Optional[str] = None
    """CodeQL Build Mode"""

    def __str__(self) -> str:
        """To String."""
        if self.language:
            return f"CodeScanningAnalysisEnvironment({self.language})"
        return "CodeScanningAnalysisEnvironment()"


@dataclass
class CodeScanningAnalysis(OctoItem):
    """Code Scanning Analysis.

    https://docs.github.com/rest/code-scanning/code-scanning#list-code-scanning-analyses-for-a-repository
    """

    id: int
    """Unique Identifier"""
    ref: str
    """Reference (branch, tag, etc)"""
    commit_sha: str
    """Commit SHA"""
    analysis_key: str
    """Analysis Key"""
    environment: CodeScanningAnalysisEnvironment
    """Environment"""
    error: str
    """Error"""
    created_at: str
    """Created At"""
    results_count: int
    """Results Count"""
    rules_count: int
    """Rules Count"""
    url: str
    """URL"""
    sarif_id: str
    """SARIF ID"""
    tool: CodeScanningTool
    """Tool Information"""
    deletable: bool
    """Deletable"""
    warning: str
    """Warning"""

    category: Optional[str] = None
    """Category"""

    def __post_init__(self) -> None:
        if isinstance(self.environment, str):
            # Load the environment as JSON
            self.environment = loadOctoItem(
                CodeScanningAnalysisEnvironment, json.loads(self.environment)
            )
        if isinstance(self.tool, dict):
            # Load the tool as JSON
            self.tool = loadOctoItem(CodeScanningTool, self.tool)

    @property
    def language(self) -> Optional[str]:
        """Language from the Environment."""
        return self.environment.language

    @property
    def build_mode(self) -> Optional[str]:
        """Build Mode from the Environment."""
        return self.environment.build_mode

    def __str__(self) -> str:
        """To String."""
        return f"CodeScanningAnalysis({self.id}, '{self.ref}', '{self.tool.name}')"


@dataclass
class CodeScanningConfiguration(OctoItem):
    """Code Scanning Configuration for Default Setup.

    https://docs.github.com/rest/code-scanning/code-scanning#get-a-code-scanning-default-setup-configuration--parameters
    """

    state: str
    """State of the Configuration"""
    query_suite: str
    """Query Suite"""
    languages: list[str]
    """Languages"""
    updated_at: str
    """Updated At"""
    schedule: str
    """Scheduled (weekly)"""

    def __str__(self) -> str:
        """To String."""
        return f"CodeScanningConfiguration('{self.state}', '{self.query_suite}', '{self.languages}')"

    def __repr__(self) -> str:
        return self.__str__()


class CodeScanning:
    """Code Scanning."""

    def __init__(
        self,
        repository: Optional[Repository] = None,
        retry_count: int = 1,
        retry_sleep: Union[int, float] = 15,
    ) -> None:
        """Code Scanning REST API.

        Retries currently are only for fetching the analyses by default is only done once.
        If you want to retry more than once you can set the `retry_count` to a higher number.
        You can also set the `retry_sleep` to a higher number to sleep longer between
        each retry.

        https://docs.github.com/en/rest/code-scanning
        """
        self.repository = repository or GitHub.repository
        self.tools: List[str] = []

        self.setup: Optional[CodeScanningConfiguration] = None

        if not self.repository:
            raise GHASToolkitError("CodeScanning requires Repository to be set")

        self.retry_count = retry_count
        self.retry_sleep = retry_sleep
        self.rest = RestRequest(self.repository)

    def isEnabled(self) -> bool:
        """Check to see if Code Scanning is enabled or not on a repository level.

        Permissions:
        - "Code scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-analyses-for-a-repository
        """
        try:
            self.getLatestAnalyses()
            return True
        except:
            logger.debug(f"Failed to get any analyses...")
        return False

    def isCodeQLDefaultSetup(self) -> bool:
        """Check if Code Scanning is using the Default CodeQL Setup.

        Permissions:
        - "Code scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning
        """
        if not self.setup:
            self.setup = self.getDefaultConfiguration()

        return self.setup.state == "configured"

    def enableDefaultSetup(
        self,
        state: str = "configured",
        query_suite: str = "default",
        languages: list[str] = [],
    ) -> dict[str, Any]:
        """Enable Code Scanning using Default Setup using CodeQL.

        Permissions:
        - "Administration" repository permissions (write)

        https://docs.github.com/en/rest/code-scanning#set-up-code-scanning
        """
        data = {"state": state, "query_suite": query_suite, "languages": languages}
        result = self.rest.patchJson(
            "/repos/{owner}/{repo}/code-scanning/default-setup",
            data,
            expected=[200, 202],
        )
        return result

    def getOrganizationAlerts(self, state: str = "open") -> list[CodeAlert]:
        """Get list of Organization Alerts.

        Permissions:
        - "Code scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning#list-code-scanning-alerts-for-an-organization
        """
        results = self.rest.get(
            "/orgs/{org}/code-scanning/alerts", {"state": state}, authenticated=True
        )
        if isinstance(results, list):
            return [loadOctoItem(CodeAlert, alert) for alert in results]

        raise GHASToolkitTypeError(
            f"Error getting alerts from Organization",
            docs="https://docs.github.com/en/rest/code-scanning#list-code-scanning-alerts-for-an-organization",
        )

    def getDefaultConfiguration(self) -> CodeScanningConfiguration:
        """Get Default Code Scanning Configuration.

        Permissions:
        - "Administration" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning/code-scanning#get-a-code-scanning-default-setup-configuration--parameters
        """
        result = self.rest.get("/repos/{owner}/{repo}/code-scanning/default-setup")
        if isinstance(result, dict):
            self.setup = loadOctoItem(CodeScanningConfiguration, result)
            return self.setup

        raise GHASToolkitTypeError(
            "Error getting default configuration",
            docs="https://docs.github.com/en/rest/code-scanning/code-scanning#get-a-code-scanning-default-setup-configuration--parameters",
        )

    def getAlerts(
        self,
        state: str = "open",
        tool_name: Optional[str] = None,
        ref: Optional[str] = None,
        sort: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> list[CodeAlert]:
        """Get all code scanning alerts.

        Permissions:
        - "Code scanning alerts" repository permissions (read)

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

        raise GHASToolkitTypeError(
            f"Error getting alerts from Repository",
            docs="https://docs.github.com/en/rest/code-scanning#list-code-scanning-alerts-for-a-repository",
        )

    def getAlertsInPR(self, base: str) -> list[CodeAlert]:
        """Get the open alerts in a Pull Request (delta / diff).

        Note this operation is slow due to it needing to lookup each alert instance
        information.

        Permissions:
        - "Code scanning alerts" repository permissions (read)
        - "Pull Requests" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning#list-instances-of-a-code-scanning-alert
        """
        results = []

        if not self.repository.reference or not self.repository.isInPullRequest():
            raise GHASToolkitError("Repository is not in a Pull Request")

        # Try merge and then head
        analysis = self.getAnalyses(reference=self.repository.reference)
        if len(analysis) == 0:
            raise GHASToolkitError("No analyses found for the PR")

        # For CodeQL results using Default Setup
        reference = analysis[0].get("ref")
        if not reference:
            raise GHASToolkitError("No ref found in the analysis")

        alerts = self.getAlerts("open", ref=reference)

        for alert in alerts:
            number = alert.get("number")
            alert_info = self.getAlertInstances(number, ref=base)
            if len(alert_info) == 0:
                results.append(alert)
        return results

    def getAlert(self, alert_number: int) -> CodeAlert:
        """Get Single Alert information from Code Scanning.

        Permissions:
        - "Code scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning#get-a-code-scanning-alert
        """
        result = self.rest.get(
            "/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}",
            {"alert_number": alert_number},
        )
        if isinstance(result, dict):
            return loadOctoItem(CodeAlert, result)
        raise GHASToolkitTypeError("Error getting alert from Repository")

    def getAlertInstances(
        self, alert_number: int, ref: Optional[str] = None
    ) -> list[dict]:
        """Get a list of alert instances.

        Permissions:
        - "Code scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning/code-scanning#list-instances-of-a-code-scanning-alert
        """
        result = self.rest.get(
            "/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
            {"alert_number": alert_number, "ref": ref},
        )
        if isinstance(result, list):
            return result

        raise GHASToolkitTypeError(
            "Error getting alert instances from Repository",
            docs="https://docs.github.com/en/rest/code-scanning/code-scanning#list-instances-of-a-code-scanning-alert",
        )

    def getAnalyses(
        self, reference: Optional[str] = None, tool: Optional[str] = None
    ) -> list[CodeScanningAnalysis]:
        """Get a list of all the analyses for a given repository.

        This function will retry X times with a Y second sleep between each retry to
        make sure the analysis is ready. This is primarily used for CodeQL Default Setup
        in Pull Requests where the analysis might not be ready yet.

        Permissions:
        - "Code scanning alerts" repository permissions (read)

        Thrown Exceptions:
        - GHASToolkitError on retry limit reached
        - GHASToolkitTypeError on error getting analyses

        https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning#list-code-scanning-analyses-for-a-repository
        """
        ref = reference or self.repository.reference
        logger.debug(f"Getting Analyses for {ref}")
        if ref is None:
            raise GHASToolkitError("Reference is required for getting analyses")

        counter = 0

        logger.debug(
            f"Fetching Analyses (retries {self.retry_count} every {self.retry_sleep}s)"
        )

        while counter < self.retry_count:
            counter += 1

            results = self.rest.get(
                "/repos/{org}/{repo}/code-scanning/analyses",
                {"tool_name": tool, "ref": ref},
            )
            if not isinstance(results, list):
                raise GHASToolkitTypeError(
                    "Error getting analyses from Repository",
                    permissions=[
                        '"Code scanning alerts" repository permissions (read)'
                    ],
                    docs="https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning#list-code-scanning-analyses-for-a-repository",
                )

            # Try default setup `head` if no results (required for default setup)
            if (
                len(results) == 0
                and self.repository.isInPullRequest()
                and (ref.endswith("/merge") or ref.endswith("/head"))
            ):
                logger.debug("No analyses found for `merge`, trying `head`")
                results = self.rest.get(
                    "/repos/{org}/{repo}/code-scanning/analyses",
                    {"tool_name": tool, "ref": ref.replace("/merge", "/head")},
                )
                if not isinstance(results, list):
                    raise GHASToolkitTypeError(
                        "Error getting analyses from Repository",
                        permissions=[
                            '"Code scanning alerts" repository permissions (read)'
                        ],
                        docs="https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning#list-code-scanning-analyses-for-a-repository",
                    )

            if len(results) < 0:
                # If the retry count is less than 1, we don't retry
                if self.retry_count < 1:
                    logger.debug(
                        f"No analyses found, retrying {counter}/{self.retry_count})"
                    )
                    time.sleep(self.retry_sleep)
            else:
                return [
                    loadOctoItem(CodeScanningAnalysis, analysis) for analysis in results
                ]

        # If we get here, we have retried the max number of times and still no results
        raise GHASToolkitError(
            "Error getting analyses from Repository (retry limit reached)",
            permissions=['"Code scanning alerts" repository permissions (read)'],
            docs="https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning#list-code-scanning-analyses-for-a-repository",
        )

    def getLatestAnalyses(
        self, reference: Optional[str] = None, tool: Optional[str] = None
    ) -> list[CodeScanningAnalysis]:
        """Get Latest Analyses for every tool.

        Permissions:
        - "Code scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning/code-scanning#get-a-code-scanning-analysis-for-a-repository
        """
        tools = set()
        results = []

        for analysis in self.getAnalyses(reference, tool):
            if analysis.tool.name in tools:
                continue
            tools.add(analysis.tool.name)
            results.append(analysis)

        self.tools = list(tools)

        return results

    def getFailedAnalyses(
        self, reference: Optional[str] = None
    ) -> list[CodeScanningAnalysis]:
        """Get Failed Analyses for a given reference. This will return all analyses with errors or warnings.

        Permissions:
        - "Code scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning/code-scanning
        """
        return [
            analysis
            for analysis in self.getAnalyses(reference)
            if analysis.error != "" or analysis.warning != ""
        ]

    def getTools(self, reference: Optional[str] = None) -> List[str]:
        """Get list of tools from the latest analyses.

        Permissions:
        - "Code scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning/code-scanning#get-a-code-scanning-analysis-for-a-repository
        """
        if len(self.tools) == 0:
            self.getLatestAnalyses(reference)
        return self.tools

    def getSarifId(self, url: str) -> int:
        """Get the latest SARIF ID from a URL."""
        if url and "/" in url:
            return int(url.split("/")[-1])
        return -1

    def downloadSARIF(self, output: str, sarif_id: int) -> bool:
        """Get SARIF by ID (UUID).

        Permissions:
        - "Code scanning alerts" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning/code-scanning#get-a-code-scanning-analysis-for-a-repository
        """
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

        Permissions:
        - "Contents" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning#list-codeql-databases-for-a-repository
        """
        result = self.rest.get("/repos/{owner}/{repo}/code-scanning/codeql/databases")
        if isinstance(result, list):
            return result

        raise GHASToolkitTypeError(
            "Error getting CodeQL databases",
            docs="https://docs.github.com/en/rest/code-scanning#list-codeql-databases-for-a-repository",
        )

    def getCodeQLDatabase(self, language: str) -> dict:
        """Get a CodeQL database for a repository.

        Permissions:
        - "Contents" repository permissions (read)

        https://docs.github.com/en/rest/code-scanning#get-a-codeql-database-for-a-repository
        """
        result = self.rest.get(
            "/repos/{owner}/{repo}/code-scanning/codeql/databases/{language}",
            {"language": language},
        )
        if isinstance(result, dict):
            return result
        raise GHASToolkitTypeError(
            "Error getting CodeQL database",
            docs="https://docs.github.com/en/rest/code-scanning#get-a-codeql-database-for-a-repository",
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
        raise GHASToolkitTypeError("Error getting CodeQL packs")

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
        raise GHASToolkitTypeError("Error getting CodeQL pack versions")

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
            raise GHASToolkitTypeError("Error getting latest release")
        version = latest_release.get("tag_name", "0.0.0")
        logger.debug(f"Latest Releases :: {version}")

        # for asset in latest_release.get("assets", []):
