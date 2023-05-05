from dataclasses import dataclass
import logging
from typing import Optional

from ghastoolkit.octokit.github import GitHub, Repository
from ghastoolkit.octokit.octokit import GraphQLRequest
from ghastoolkit.supplychain.advisories import Advisory
from ghastoolkit.supplychain.dependencyalert import DependencyAlert


logger = logging.getLogger("ghastoolkit.octokit.dependabot")


class Dependabot:
    def __init__(self, repository: Optional[Repository] = None) -> None:
        self.repository = repository or GitHub.repository
        self.graphql = GraphQLRequest(repository)

    def getAlerts(self) -> list[DependencyAlert]:
        """Get Dependabot alerts from GraphQL API"""
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

                advisory = Advisory(
                    ghsa_id=data.get("securityAdvisory", {}).get("ghsaId"),
                    severity=data.get("securityAdvisory", {}).get("severity"),
                    # TODO: CWE info
                )
                dep_alert = DependencyAlert(
                    severity=advisory.severity, purl=purl, advisory=advisory
                )
                dep_alert.__data__ = data
                results.append(dep_alert)

            if not alerts.get("pageInfo", {}).get("hasNextPage"):
                logger.debug(f"GraphQL cursor hit end page")
                break

            self.graphql.cursor = alerts.get("pageInfo", {}).get("endCursor", "")

        logger.debug(f"Number of Dependabot Alerts :: {len(results)}")
        return results
