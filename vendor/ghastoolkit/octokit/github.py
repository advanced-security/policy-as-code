"""GitHub and Repository APIs."""

import logging
import os
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from semantic_version import Version

from ghastoolkit.errors import GHASToolkitError
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
    """GitHub Access Token
    This is used to authenticate with the GitHub API.

    This can be set using the GITHUB_TOKEN environment variable or
    passed in as a parameter.
    """

    token_type: Optional[str] = None
    """GitHub Token Type"""

    # URLs
    instance: str = "https://github.com"
    """Instance"""
    api_rest: str = "https://api.github.com"
    """REST API URL"""
    api_graphql: str = "https://api.github.com/graphql"
    """GraphQL API URL"""

    server_version: Optional[Version] = None
    """GitHub Enterprise Server Version"""

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

        # Set token or load from environment
        if token:
            GitHub.token = token
        else:
            GitHub.loadToken()
        GitHub.token_type = GitHub.validateTokenType(GitHub.token)

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

    @staticmethod
    def loadToken():
        """Load the GitHub token from the environment variable."""
        if envvar := os.environ.get("GITHUB_TOKEN"):
            GitHub.token = envvar
            logger.debug("Loaded GITHUB_TOKEN from environment variable")

            GitHub.validateTokenType(GitHub.token)
        elif envvar := os.environ.get("GH_TOKEN"):
            # This is sometimes set by GitHub CLI
            GitHub.token = envvar
            logger.debug("Loaded GH_TOKEN from environment variable")

        else:
            # TODO: Load from GH CLI?
            logger.debug("Failed to load GitHub token")

    @staticmethod
    def getToken(masked: bool = True) -> Optional[str]:
        """Get the GitHub token.

        Masking the token will only show the first 5 and all the other
        characters as `#`.

        Args:
            masked (bool): Mask the token. Defaults to True.

        Returns:
            str: The GitHub token.
        """
        if not GitHub.token:
            return None

        if masked:
            last = len(GitHub.token) - 5
            return f"{GitHub.token[0:5]}{'#' * last}"
        return GitHub.token

    @property
    def github_app(self) -> bool:
        """Check if the token is a GitHub App token."""
        # This is for backwards compatibility
        if ttype := self.token_type:
            return ttype == "OAUTH"
        return False

    @staticmethod
    def validateTokenType(token: Optional[str]) -> Optional[str]:
        """Check what type of token is being used.

        Returns:
            str: The type of token being used.
                - "PAT" for Personal Access Token
                - "OAUTH" for GitHub App token / OAuth token
                - "ACTIONS" for GitHub Actions token
                - "SERVICES" for Server-to-Server token
                - "UNKNOWN" for unknown token type

        https://github.blog/engineering/behind-githubs-new-authentication-token-formats/
        """
        if not token or not isinstance(token, str):
            return None

        # GitHub Actions sets the GITHUB_SECRET_SOURCE environment variable
        if secret_source := os.environ.get("GITHUB_SECRET_SOURCE"):
            if secret_source != "None":
                return secret_source.upper()

        if token.startswith("ghp_") or token.startswith("github_pat_"):
            return "PAT"
        elif token.startswith("gho_"):
            # GitHub OAuth tokens are used for GitHub Apps or GH CLI
            return "OAUTH"
        elif token.startswith("ghs_"):
            # GitHub Actions token are Server-to-Server tokens
            if os.environ.get("CI") == "true":
                return "ACTIONS"
            return "SERVICES"
