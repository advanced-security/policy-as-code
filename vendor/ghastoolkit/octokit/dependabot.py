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
            self.graphql.query(
                "GetDependencyStatus",
                options={"owner": self.repository.owner, "repo": self.repository.repo},
            )
            return True
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

    def getAlerts(self) -> list[DependencyAlert]:
        """Get All Dependabot alerts from GraphQL API using the `GetDependencyAlerts` query."""
        results = []

        while True:
            data = self.graphql.query(
                "GetDependencyAlerts",
                options={"owner": self.repository.owner, "repo": self.repository.repo},
            )
            alerts = (
                data.get("data", {})
                .get("repository", {})
                .get("vulnerabilityAlerts", {})
            )

            for alert in alerts.get("edges", []):
                data = alert.get("node", {})
                package = data.get("securityVulnerability", {}).get("package", {})
                purl = f"pkg:{package.get('ecosystem')}/{package.get('name')}".lower()
                created_at = data.get("createdAt")

                advisory = Advisory(
                    ghsa_id=data.get("securityAdvisory", {}).get("ghsaId"),
                    severity=data.get("securityAdvisory", {}).get("severity"),
                    # TODO: CWE info
                )
                dep_alert = DependencyAlert(
                    severity=advisory.severity,
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
