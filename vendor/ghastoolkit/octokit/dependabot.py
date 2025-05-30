"""Dependabot API."""

import logging
from typing import Optional, Any

from ghastoolkit.errors import GHASToolkitError, GHASToolkitTypeError
from ghastoolkit.octokit.github import GitHub, Repository
from ghastoolkit.octokit.octokit import GraphQLRequest, RestRequest
from ghastoolkit.supplychain.advisories import Advisory
from ghastoolkit.supplychain.dependencyalert import DependencyAlert


logger = logging.getLogger("ghastoolkit.octokit.dependabot")


class Dependabot:
    """Dependabot API instance."""

    def __init__(self, repository: Optional[Repository] = None) -> None:
        """Initialise Dependabot API class."""
        self.repository = repository or GitHub.repository
        self.graphql = GraphQLRequest(repository)

        self.rest = RestRequest(repository)

    def isEnabled(self) -> bool:
        """Is Dependabot enabled."""
        try:
            data = self.graphql.query(
                "GetDependencyStatus",
                options={"owner": self.repository.owner, "repo": self.repository.repo},
            )
            return (
                data.get("data", {})
                .get("repository", {})
                .get("hasVulnerabilityAlertsEnabled", False)
            )
        except:
            logger.debug(f"Failed to get alert count")
        return False

    def isSecurityUpdatesEnabled(self) -> bool:
        """Is Security Updates for Dependabot enabled.

        https://docs.github.com/en/rest/reference/repos#get-a-repository
        """
        result = self.rest.get("get/repos/{owner}/{repo}")
        if not isinstance(result, dict):
            raise GHASToolkitTypeError(
                "Unable to get repository info",
                permissions=["Repository Administration (read)"],
                docs="https://docs.github.com/en/rest/reference/repos#get-a-repository",
            )
        saa = result.get("source", {}).get("security_and_analysis", {})
        status = saa.get("dependabot_security_updates", {}).get("status", "disabled")
        return status == "enabled"

    def getEnterpriseAlerts(
        self,
        state: str = "open",
        severity: Optional[str] = None,
        ecosystem: Optional[str] = None,
        package: Optional[str] = None,
        manifest: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> list[DependencyAlert]:
        """Get all Dependabot alerts from Enterprise.

        Arguments:
            severity (str): Severity of the alert.
                Options: low, moderate, high, critical
            ecosystem (str): Ecosystem of the alert.
                Options: npm, rubygems, maven, pip, etc.
            package (str): Package name of the alert.
            manifest (str): Manifest path of the alert.
            scope (str): Scope of the alert.
        Returns:
            list[DependencyAlert]: List of Dependabot alerts.
        Raises:
            GHASToolkitAuthenticationError: If the request fails due to authentication.
            GHASToolkitTypeError: If the state is not valid.
            GHASToolkitError: If the request fails.
        """
        parameters = self._validateInput(
            {
                "state": state,
                "severity": severity,
                "ecosystem": ecosystem,
                "package": package,
                "manifest": manifest,
                "scope": scope,
            }
        )
        results = self.rest.get(
            "/enterprises/{enterprise}/dependabot/alerts", parameters
        )
        if isinstance(results, list):
            return self._apiToAlerts(results)

        logger.debug(f"Failed to get Dependabot alerts :: {results}")
        raise GHASToolkitTypeError(
            "Error getting Dependabot organization alerts",
            docs="https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-an-enterprise",
            permissions=[
                '"Dependabot alerts" repository permissions (read)',
                '"Dependabot security updates" repository permissions (read)',
            ],
        )

    def getOrganizationAlerts(
        self,
        state: str = "open",
        severity: Optional[str] = None,
        ecosystem: Optional[str] = None,
        package: Optional[str] = None,
        manifest: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> list[DependencyAlert]:
        """Get all Dependabot alerts from organization.

        Arguments:
            state (str): State of the alert. Defaults to "open".
                Options: auto_dismissed, dismissed, fixed, open
            severity (str): Severity of the alert.
                Options: low, moderate, high, critical
            ecosystem (str): Ecosystem of the alert.
                Options: npm, rubygems, maven, pip, etc.
            package (str): Package name of the alert.
            manifest (str): Manifest path of the alert.
            scope (str): Scope of the alert.
        Returns:
            list[DependencyAlert]: List of Dependabot alerts.
        Raises:
            GHASToolkitAuthenticationError: If the request fails due to authentication.
            GHASToolkitTypeError: If the state is not valid.
            GHASToolkitError: If the request fails.
        """
        parameters = self._validateInput(
            {
                "state": state,
                "severity": severity,
                "ecosystem": ecosystem,
                "package": package,
                "manifest": manifest,
                "scope": scope,
            }
        )
        results = self.rest.get("/orgs/{org}/dependabot/alerts", parameters)
        if isinstance(results, list):
            return self._apiToAlerts(results)

        logger.debug(f"Failed to get Dependabot alerts :: {results}")
        raise GHASToolkitTypeError(
            "Error getting Dependabot organization alerts",
            docs="https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-an-organization",
            permissions=[
                '"Dependabot alerts" repository permissions (read)',
                '"Dependabot security updates" repository permissions (read)',
            ],
        )

    def getAlerts(
        self,
        state: str = "open",
        severity: Optional[str] = None,
        ecosystem: Optional[str] = None,
        package: Optional[str] = None,
        manifest: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> list[DependencyAlert]:
        """Get All Dependabot alerts from REST API.

        Arguments:
            state (str): State of the alert. Defaults to "open".
                Options: auto_dismissed, dismissed, fixed, open
            severity (str): Severity of the alert.
                Options: low, moderate, high, critical
            ecosystem (str): Ecosystem of the alert.
                Options: npm, rubygems, maven, pip, etc.
            package (str): Package name of the alert.
            manifest (str): Manifest path of the alert.
            scope (str): Scope of the alert.

        Returns:
            list[DependencyAlert]: List of Dependabot alerts.

        Raises:
            GHASToolkitTypeError: If the state is not valid.
            GHASToolkitError: If the request fails.

        https://docs.github.com/en/rest/dependabot/alerts
        """
        parameters = self._validateInput(
            {
                "state": state,
                "severity": severity,
                "ecosystem": ecosystem,
                "package": package,
                "manifest": manifest,
                "scope": scope,
            }
        )
        results = self.rest.get("/repos/{owner}/{repo}/dependabot/alerts", parameters)

        if isinstance(results, list):
            return self._apiToAlerts(results)

        logger.debug(f"Failed to get Dependabot alerts :: {results}")
        raise GHASToolkitTypeError(
            f"Error getting Dependabot alerts",
            docs="https://docs.github.com/en/rest/dependabot/alerts",
            permissions=[
                '"Dependabot alerts" repository permissions (read)',
                '"Dependabot security updates" repository permissions (read)',
            ],
        )

    def getAlertsInPR(self) -> list[DependencyAlert]:
        """Get All Dependabot alerts from REST API in Pull Request."""
        logger.debug("Dependabot Alerts from Pull Request using DependencyGraph API")

        from ghastoolkit import DependencyGraph

        depgraph = DependencyGraph(repository=self.repository)

        pr_info = self.repository.getPullRequestInfo()
        pr_base = pr_info.get("base", {}).get("ref", "")
        pr_head = pr_info.get("head", {}).get("ref", "")

        if pr_base == "" or pr_head == "":
            raise GHASToolkitError(
                "Failed to get base and head branch of pull request",
                permissions=[
                    '"Contents" repository permissions (read)',
                    '"Pull requests" permissions (read)',
                ],
                docs="https://docs.github.com/en/rest/reference/repos#get-a-repository",
            )

        dependencies = depgraph.getDependenciesInPR(pr_base, pr_head)
        alerts = []
        for dep in dependencies:
            alerts.extend(dep.alerts)
        return alerts

    def getAlertsGraphQL(self) -> list[DependencyAlert]:
        """Get All Dependabot alerts from GraphQL API using the `GetDependencyAlerts` query."""
        results = []

        while True:
            data = self.graphql.query(
                "GetDependencyAlerts",
                options={"owner": self.repository.owner, "repo": self.repository.repo},
            )
            repo = data.get("data", {}).get("repository", {})
            if not repo:
                logger.error(f"Failed to get GraphQL repository")
                logger.error(
                    "This could be due to a lack of permissions or access token"
                )
                raise GHASToolkitError(f"Failed to get GraphQL repository alerts")
            logger.debug("GraphQL successfully got repository data")

            alerts = repo.get("vulnerabilityAlerts", {}).get("edges", [])
            page_info = repo.get("vulnerabilityAlerts", {}).get("pageInfo", {})

            for alert in alerts:
                data = alert.get("node", {})
                package = data.get("securityVulnerability", {}).get("package", {})
                ecosystem = package.get("ecosystem", "")
                name = package.get("name", "")
                purl = f"pkg:{ecosystem}/{name}".lower()
                created_at = data.get("createdAt")

                advisory_data = data.get("securityAdvisory", {})
                # Fix issues between GraphQL and Advisory class
                advisory_data["ghsa_id"] = advisory_data.pop("ghsaId")
                advisory = Advisory(**advisory_data)
                logger.debug(f"Advisory :: {advisory}")

                dep_alert = DependencyAlert(
                    number=data.get("number"),
                    state=data.get("state"),
                    severity=advisory.severity.lower(),
                    purl=purl,
                    advisory=advisory,
                    created_at=created_at,
                )
                dep_alert.__data__ = data

                logger.debug(f"Alert :: {dep_alert}")
                results.append(dep_alert)

            if not page_info.get("pageInfo", {}).get("hasNextPage"):
                logger.debug(f"GraphQL cursor hit end page")
                break

            self.graphql.cursor = page_info.get("pageInfo", {}).get("endCursor", "")
            logger.debug(f"GraphQL cursor :: {self.graphql.cursor}")

        logger.debug(f"Number of Dependabot Alerts :: {len(results)}")
        return results

    def _validateInput(self, parameters: dict[str, Any]) -> dict[str, Any]:
        """Validates the input parameters for the API request."""
        if state := parameters.get("state"):
            if state not in [
                "auto_dismissed",
                "dismissed",
                "fixed",
                "open",
            ]:
                raise GHASToolkitTypeError(
                    f"Invalid state provided: {state}",
                    docs="https://docs.github.com/en/rest/dependabot/alerts",
                )
        else:
            parameters["state"] = "open"
        logger.debug(f"Getting Dependabot alerts with state: {parameters.get('state')}")

        if severity := parameters.get("severity"):
            if severity not in ["low", "moderate", "high", "critical"]:
                raise GHASToolkitTypeError(
                    f"Invalid severity provided: {severity}",
                    docs="https://docs.github.com/en/rest/dependabot/alerts",
                )
        return parameters

    def _apiToAlerts(self, alerts: list[dict[str, Any]]) -> list[DependencyAlert]:
        retval = []
        for alert in alerts:
            advisory_data = alert.get("security_advisory", {})
            # Fix issues between GraphQL and Advisory class
            advisory_data["affected"] = advisory_data.pop("vulnerabilities")
            advisory = Advisory(**advisory_data)
            logger.debug(f"Advisory :: {advisory}")

            package = alert.get("dependency", {}).get("package", {})

            alert = DependencyAlert(
                number=alert.get("number"),
                state=alert.get("state"),
                severity=alert.get("security_advisory", {}).get("severity", "unknown"),
                advisory=advisory,
                purl=f"pkg:{package.get('ecosystem')}/{package.get('name')}".lower(),
                manifest=alert.get("manifest_path"),
            )
            logger.debug(f"Alert :: {alert}")

            retval.append(alert)

        logger.debug(f"Number of Dependabot Alerts :: {len(retval)}")
        return retval
