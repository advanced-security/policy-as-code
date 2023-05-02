import logging
from typing import Optional

from ghastoolkit import GitHub, Repository
from ghastoolkit.octokit.octokit import GraphQLRequest


logger = logging.getLogger("ghastoolkit.octokit.dependabot")


class Dependabot:
    def __init__(self, repository: Optional[Repository] = None) -> None:
        self.repository = repository or GitHub.repository
        self.graphql = GraphQLRequest(repository)

    def getAlerts(self) -> list[dict]:
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
                results.append(alert.get("node", {}))

            if not alerts.get("pageInfo", {}).get("hasNextPage"):
                logger.debug(f"GraphQL cursor hit end page")
                break

            self.graphql.cursor = alerts.get("pageInfo", {}).get("endCursor", "")

        logger.debug(f"Number of Dependabot Alerts :: {len(results)}")
        return results
