"""Dependabot API."""
import logging
from typing import Optional

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
        """Is Security Updates for Dependabot enabled."""
        result = self.rest.get("get/repos/{owner}/{repo}")
        if not isinstance(result, dict):
            raise Exception(f"Unable to get repository info")
        saa = result.get("source", {}).get("security_and_analysis", {})
        status = saa.get("dependabot_security_updates", {}).get("status", "disabled")
        return status == "enabled"

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

        https://docs.github.com/en/enterprise-cloud@latest/rest/dependabot/alerts?apiVersion=2022-11-28
        """
        if state not in ["auto_dismissed", "dismissed", "fixed", "open"]:
            raise Exception(f"Invalid state provided: {state}")

        logger.debug(f"Getting Dependabot alerts with state: {state}")

        results = self.rest.get(
            "/repos/{owner}/{repo}/dependabot/alerts",
            {
                "state": state,
                "severity": severity,
                "ecosystem": ecosystem,
                "package": package,
                "manifest": manifest,
                "scope": scope,
            },
        )
        if isinstance(results, list):
            retval = []
            for alert in results:
                advisory_data = alert.get("security_advisory", {})
                # Fix issues between GraphQL and Advisory class
                advisory_data["affected"] = advisory_data.pop("vulnerabilities")
                advisory = Advisory(**advisory_data)

                package = alert.get("dependency", {}).get("package", {})

                retval.append(
                    DependencyAlert(
                        number=alert.get("number"),
                        state=alert.get("state"),
                        severity=alert.get("security_advisory", {}).get(
                            "severity", "unknown"
                        ),
                        advisory=advisory,
                        purl=f"pkg:{package.get('ecosystem')}/{package.get('name')}".lower(),
                    )
                )

            return retval
        raise Exception(f"Error getting Dependabot alerts")

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
                raise Exception(f"Failed to get GraphQL repository alerts")
            alerts = repo.get("vulnerabilityAlerts", {})

            for alert in alerts.get("edges", []):
                data = alert.get("node", {})
                package = data.get("securityVulnerability", {}).get("package", {})
                purl = f"pkg:{package.get('ecosystem')}/{package.get('name')}".lower()
                created_at = data.get("createdAt")

                advisory_data = data.get("securityAdvisory", {})
                # Fix issues between GraphQL and Advisory class
                advisory_data["ghsa_id"] = advisory_data.pop("ghsaId")
                advisory = Advisory(**advisory_data)

                dep_alert = DependencyAlert(
                    number=data.get("number"),
                    state=data.get("state"),
                    severity=advisory.severity.lower(),
                    purl=purl,
                    advisory=advisory,
                    created_at=created_at,
                )
                dep_alert.__data__ = data
                results.append(dep_alert)

            if not alerts.get("pageInfo", {}).get("hasNextPage"):
                logger.debug(f"GraphQL cursor hit end page")
                break

            self.graphql.cursor = alerts.get("pageInfo", {}).get("endCursor", "")

        logger.debug(f"Number of Dependabot Alerts :: {len(results)}")
        return results
