import logging
from typing import List, Optional

from ghastoolkit.octokit.github import GitHub
from ghastoolkit.octokit.octokit import Octokit, RestRequest
from ghastoolkit.octokit.repository import Repository

logger = logging.getLogger("ghastoolkit.octokit.enterprise")


class Organization:
    """Organization."""

    def __init__(
        self, organization: Optional[str] = None, identifier: Optional[int] = None
    ) -> None:
        """Initialise Organization."""
        self.name = organization
        self.identifier = identifier

        self.rest = RestRequest(GitHub.repository)

    def getRepositories(self) -> List[Repository]:
        """Get Repositories."""
        repositories = []
        result = self.rest.get(f"/orgs/{self.name}/repos")
        if not isinstance(result, list):
            logger.error("Error getting repositories")
            return []

        for repository in result:
            repositories.append(Repository.parseRepository(repository.get("full_name")))

        return repositories

    def enableAllSecurityProduct(self) -> bool:
        """Enable all security products."""
        products = [
            "advanced_security",
            "dependency_graph",
            "dependabot_alerts",
            "dependabot_security_updates",
            "code_scanning_default_setup",
            "secret_scanning",
            "secret_scanning_push_protection",
        ]
        for product in products:
            rslt = self.enableSecurityProduct(product)
            if not rslt:
                return False

        return True

    def enableSecurityProduct(self, security_product: str) -> bool:
        """Enable Advanced Security."""
        url = Octokit.route(
            f"/orgs/{self.name}/{security_product}/enable_all", GitHub.repository
        )
        result = self.rest.session.post(url)
        if result.status_code != 204:
            logger.error("Error enabling security product")
            return False

        return True

    def __str__(self) -> str:
        """Return string representation."""
        return f"Organization('{self.name}')"


class Enterprise:
    """Enterprise API."""

    def __init__(
        self,
        enterprise: Optional[str] = None,
    ) -> None:
        """Initialise Enterprise."""
        self.enterprise = enterprise or GitHub.enterprise
        self.rest = RestRequest(GitHub.repository)

    def getOrganizations(self, include_github: bool = False) -> List[Organization]:
        """Get all the Organizations in an enterprise.

        You will need to be authenticated as an enterprise owner to use this API.
        """
        github_orgs = ["github", "actions"]
        organizations = []
        url = Octokit.route("/organizations", GitHub.repository)
        # pagination uses a different API versus the rest of the API
        # https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#list-organizations
        last_org_id = 1

        while True:
            response = self.rest.session.get(
                url, params={"since": last_org_id, "per_page": 100}
            )

            if response.status_code != 200:
                logger.error("Error getting organizations")
                return []

            result = response.json()

            if not isinstance(result, list):
                logger.error("Error getting organizations")
                return []

            for org in result:
                if not include_github and org.get("login") in github_orgs:
                    continue
                organizations.append(Organization(org.get("login"), org.get("id")))

            if len(result) < 100:
                break

            if len(organizations) == 0:
                logger.error("Error getting last org in organizations")
                logger.error("Only GitHub orgs might be returned")
                break

            # set last org ID
            last_org_id = organizations[-1].identifier

        return organizations
