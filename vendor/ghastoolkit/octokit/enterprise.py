import logging
from typing import List, Optional

from semantic_version import Version

from ghastoolkit.errors import GHASToolkitError
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
        """Get Repositories.

        https://docs.github.com/en/rest/repos/repos#list-organization-repositories
        """
        repositories = []
        result = self.rest.get(f"/orgs/{self.name}/repos")
        if not isinstance(result, list):
            logger.error("Error getting repositories")
            raise GHASToolkitError(
                "Error getting repositories",
                permissions=["Metadata repository permissions (read)"],
                docs="https://docs.github.com/en/rest/repos/repos#list-organization-repositories",
            )

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

    def enableDefaultSetup(self) -> bool:
        """Enable Code Scanning Default Setup on all repositories in an organization.
        Assumes that advanced-security is enabled on all repositories.

        - GHE cloud: supported
        - GHE server: 3.8 or lower: not supported
        - GHE server: 3.9 or 3.10: uses repo level setup (may take a while)
        - GHE server: 3.11 or above: not supported
        """

        if GitHub.isEnterpriseServer():
            # version 3.8 or lower
            if GitHub.server_version and GitHub.server_version < Version("3.9.0"):
                logger.error(
                    "Enterprise Server 3.8 or lower does not support default setup"
                )
                raise GHASToolkitError(
                    "Enterprise Server 3.8 or lower does not support default setup"
                )

            elif GitHub.server_version and GitHub.server_version < Version("3.11.0"):
                from ghastoolkit.octokit.codescanning import CodeScanning

                logger.debug("Enterprise Server 3.9/3.10 supports repo level setup")

                for repo in self.getRepositories():
                    logger.debug(f"Enabling default setup for {repo.repo}")

                    code_scanning = CodeScanning(repo)
                    code_scanning.enableDefaultSetup()
                return True
            else:
                logger.error(
                    "Enterprise Server 3.11 or above isn't supported by this version of the toolkit"
                )
        else:
            self.enableSecurityProduct("code_scanning_default_setup")
            return True
        return False

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
                raise GHASToolkitError(
                    "Error getting organizations",
                    permissions=["Metadata repository permissions (read)"],
                    docs="https://docs.github.com/en/rest/orgs/orgs#list-organizations",
                )

            result = response.json()

            if not isinstance(result, list):
                logger.error("Error getting organizations")
                raise GHASToolkitError(
                    "Error getting organizations",
                    permissions=["Metadata repository permissions (read)"],
                    docs="https://docs.github.com/en/rest/orgs/orgs#list-organizations",
                )

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

    def enableDefaultSetup(self):
        """Enable Code Scanning default setup on all repositories in an enterprise.

        Assumes that advanced-security is enabled on all repositories.

        - GHE cloud: supported
        - GHE server: 3.8 or lower: not supported
        - GHE server: 3.9 or 3.10: uses repo level setup
        - GHE server: 3.11 or above: uses default setup
        """

        for organization in self.getOrganizations():
            organization.enableDefaultSetup()
