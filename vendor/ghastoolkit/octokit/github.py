"""GitHub and Repository APIs."""

import logging
import os
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from semantic_version import Version

from ghastoolkit.octokit.repository import Repository


logger = logging.getLogger("ghastoolkit.octokit.github")


class GitHub:
    """The GitHub Class.

    This API is used to configure the state for all Octokit apis.
    Its a standard interface across all projects.
    """

    repository: Repository = Repository("GeekMasher", "ghastoolkit")
    """Repository"""

    owner: Optional[str] = None
    """Owner / Organisation"""

    enterprise: Optional[str] = None
    """Enterprise Name"""

    token: Optional[str] = None
    """GitHub Access Token"""

    # URLs
    instance: str = "https://github.com"
    """Instance"""
    api_rest: str = "https://api.github.com"
    """REST API URL"""
    api_graphql: str = "https://api.github.com/graphql"
    """GraphQL API URL"""

    server_version: Optional[Version] = None
    """GitHub Enterprise Server Version"""

    github_app: bool = False
    """GitHub App setting"""

    @staticmethod
    def init(
        repository: Optional[str] = None,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        reference: Optional[str] = None,
        branch: Optional[str] = None,
        token: Optional[str] = None,
        instance: Optional[str] = None,
        enterprise: Optional[str] = None,
        retrieve_metadata: bool = True,
    ) -> None:
        """Initialise a GitHub class using a number of properties."""
        if repository and "/" in repository:
            GitHub.repository = Repository.parseRepository(repository)
            GitHub.owner = GitHub.repository.owner
        elif repository or owner:
            GitHub.owner = owner or repository
        elif owner and repo:
            GitHub.repository = Repository(owner, repo)
            GitHub.owner = owner

        if GitHub.repository:
            if reference:
                GitHub.repository.reference = reference
            if branch:
                GitHub.repository.branch = branch

        if not token:
            token = os.environ.get("GITHUB_TOKEN")
        GitHub.token = token

        if not instance:
            instance = os.environ.get("GITHUB_SERVER_URL")

        # instance
        if instance and instance != "":
            GitHub.instance = instance
            GitHub.api_rest, GitHub.api_graphql = GitHub.parseInstance(instance)

            if GitHub.isEnterpriseServer() and retrieve_metadata:
                # Get the server version
                GitHub.getMetaInformation()

        GitHub.enterprise = enterprise

        return

    @staticmethod
    def parseInstance(instance: str) -> Tuple[str, str]:
        """Parse GitHub Instance."""
        url = urlparse(instance)

        # GitHub Cloud (.com)
        if url.netloc == "github.com":
            api = url.scheme + "://api." + url.netloc
            return (api, f"{api}/graphql")
        # GitHub Ent Server
        api = url.scheme + "://" + url.netloc + "/api"

        return (f"{api}/v3", f"{api}/graphql")

    @staticmethod
    def isEnterpriseServer() -> bool:
        """Is the GitHub instance an Enterprise Server."""
        return GitHub.instance != "https://github.com"

    @staticmethod
    def display() -> str:
        """Display the GitHub Settings."""
        return f"GitHub('{GitHub.repository.display()}', '{GitHub.instance}')"

    @staticmethod
    def getOrganization() -> str:
        """Get the Organization."""
        return GitHub.owner or GitHub.repository.owner

    @staticmethod
    def getMetaInformation() -> Dict:
        """Get the GitHub Meta Information."""
        from ghastoolkit.octokit.octokit import RestRequest

        response = RestRequest().session.get(f"{GitHub.api_rest}/meta")

        if response.headers.get("X-GitHub-Enterprise-Version"):
            version = response.headers.get("X-GitHub-Enterprise-Version")
            GitHub.server_version = Version(version)

        return response.json()
