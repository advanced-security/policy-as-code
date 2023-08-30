"""GitHub and Repository APIs."""
import logging
import os
import shutil
import tempfile
import subprocess
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Union
from urllib.parse import urlparse

from semantic_version import Version


logger = logging.getLogger("ghastoolkit.octokit.github")


@dataclass
class Repository:
    """GitHub Repository."""

    owner: str
    """Owner"""
    repo: str
    """Repository name"""

    reference: Optional[str] = None
    """Reference (`refs/heads/main`)"""
    branch: Optional[str] = None
    """Branch / Tab name"""

    __prinfo__: Optional[dict] = None

    sha: Optional[str] = None
    """Git SHA"""

    clone_path: Optional[str] = None
    """Clone Path"""

    repo_token: Optional[str] = None
    """Repository Access Token"""

    is_github_app_token: bool = False
    """Whether the token is a GitHub App Token"""

    def __post_init__(self) -> None:
        if self.reference and not self.branch:
            if not self.isInPullRequest():
                _, _, branch = self.reference.split("/", 2)
                self.branch = branch
        if self.branch and not self.reference:
            self.reference = f"refs/heads/{self.branch}"

        if not self.clone_path:
            self.clone_path = os.path.join(tempfile.gettempdir(), self.repo)

    def __str__(self) -> str:
        """To String."""
        name = f"{self.owner}/{self.repo}"
        if self.reference:
            return f"{name}:{self.reference}"
        elif self.branch:
            return f"{name}@{self.branch}"
        return name

    def __repr__(self) -> str:
        return self.__str__()

    def __hash__(self) -> int:
        return hash(self.__str__())

    def isInPullRequest(self) -> bool:
        """Check if the current reference is in a Pull Request."""
        if self.reference:
            return self.reference.startswith("refs/pull")
        return False

    def getPullRequestNumber(self) -> int:
        """Get Pull Request Number / ID."""
        if self.isInPullRequest() and self.reference:
            return int(self.reference.split("/")[2])
        return 0

    def getPullRequestInfo(self) -> dict:
        """Get information for the current Pull Request.

        https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#get-a-pull-request
        """
        if not self.__prinfo__:
            from ghastoolkit.octokit.octokit import RestRequest

            pull_number = self.getPullRequestNumber()
            self.__prinfo__ = RestRequest().get(
                "/repos/{owner}/{repo}/pulls/{pull_number}",
                {"pull_number": pull_number},
            )
        return self.__prinfo__

    def getPullRequestCommits(self) -> list[str]:
        """Get list of Pull Request commits."""
        result = []
        if self.isInPullRequest():
            from ghastoolkit.octokit.octokit import RestRequest

            pull_number = self.getPullRequestNumber()
            response = RestRequest().get(
                "/repos/{owner}/{repo}/pulls/{pull_number}/commits",
                {"pull_number": pull_number},
            )
            for commit in response:
                result.append(commit.get("sha"))
        return result

    def getPullRequestComments(self) -> list[dict[str, Union[int, str]]]:
        """Get list of Pull Request comments."""
        result = []
        if self.isInPullRequest():
            from ghastoolkit.octokit.octokit import RestRequest

            issue_number = self.getPullRequestNumber()
            response = RestRequest().get(
                "/repos/{owner}/{repo}/issues/{issue_number}/comments",
                {"issue_number": issue_number},
            )
            for comment in response:
                result.append(
                    {
                        "id": comment.get("id"),
                        "body": comment.get("body", ""),
                    }
                )
        return result

    def createPullRequestComment(self, comment_body: str) -> None:
        """Create a new Pull Request comment."""
        if self.isInPullRequest():
            from ghastoolkit.octokit.octokit import RestRequest

            issue_number = self.getPullRequestNumber()
            RestRequest().postJson(
                "/repos/{owner}/{repo}/issues/{issue_number}/comments",
                {"body": comment_body},
                expected=201,
                parameters={"issue_number": issue_number},
            )
        return

    def updatePullRequestComment(self, comment_id: int, comment_body: str) -> None:
        """Update an existing Pull Request comment."""
        if self.isInPullRequest():
            from ghastoolkit.octokit.octokit import RestRequest

            RestRequest().patchJson(
                "/repos/{owner}/{repo}/issues/comments/{comment_id}",
                {"body": comment_body},
                expected=200,
                parameters={"comment_id": comment_id},
            )
        return

    @property
    def clone_url(self) -> str:
        """Repository clone URL."""
        url = urlparse(GitHub.instance)
        if self.repo_token:
            if self.is_github_app_token:
                return f"{url.scheme}://x-access-token:{self.repo_token}@{url.netloc}/{self.owner}/{self.repo}"
            else:
                return f"{url.scheme}://{self.repo_token}@{url.netloc}/{self.owner}/{self.repo}"
        elif GitHub.github_app:
            return f"{url.scheme}://x-access-token:{GitHub.token}@{url.netloc}/{self.owner}/{self.repo}.git"
        elif GitHub.token:
            return f"{url.scheme}://{GitHub.token}@{url.netloc}/{self.owner}/{self.repo}.git"
        return f"{GitHub.instance}/{self.owner}/{self.repo}.git"

    def _cloneCmd(self, path: str, depth: Optional[int] = None) -> list[str]:
        cmd = ["git", "clone"]
        if self.branch:
            cmd.extend(["-b", self.branch])
        if depth:
            cmd.extend(["--depth", str(depth)])
        cmd.extend([self.clone_url, path])
        return cmd

    def clone(
        self,
        path: Optional[str] = None,
        clobber: bool = False,
        depth: Optional[int] = None,
    ):
        """Clone Repository based on url.

        path: str - if left `None`, it will create a tmp folder for you.
        """
        if path:
            self.clone_path = path
        if not self.clone_path:
            raise Exception(f"Clone path not set")

        if os.path.exists(self.clone_path) and clobber:
            logger.debug(f"Path exists but deleting it ready for cloning")
            shutil.rmtree(self.clone_path)

        elif not clobber and os.path.exists(self.clone_path):
            logger.debug("Cloned repository already exists")
            return

        cmd = self._cloneCmd(self.clone_path, depth=depth)
        logger.debug(f"Cloning Command :: {cmd}")

        with open(os.devnull, "w") as null:
            subprocess.check_call(cmd, stdout=null, stderr=null)

    def gitsha(self) -> str:
        """Get the current Git SHA."""
        cmd = ["git", "rev-parse", "HEAD"]
        result = (
            subprocess.check_output(cmd, cwd=self.clone_path).decode("ascii").strip()
        )
        return result

    def getFile(self, path: str) -> str:
        """Get a path relative from the base of the cloned repository."""
        if not self.clone_path:
            raise Exception(f"Unknown clone path")
        return os.path.join(self.clone_path, path)

    def display(self) -> str:
        """Display the repository as a string."""
        if self.reference:
            return f"{self.owner}/{self.repo}@{self.reference}"
        return f"{self.owner}/{self.repo}"

    @staticmethod
    def parseRepository(name: str) -> "Repository":
        """Parse the repository name."""
        ref = None
        branch = None
        if "@" in name:
            name, branch = name.split("@", 1)
            ref = f"refs/heads/{branch}"

        owner, repo = name.split("/", 1)
        return Repository(owner, repo, reference=ref, branch=branch)


class GitHub:
    """The GitHub Class.

    This API is used to configure the state for all Octokit apis.
    Its a standard interface across all projects.
    """

    repository: Repository = Repository("GeekMasher", "ghastoolkit")
    """Repository"""
    token: Optional[str] = None
    """GitHub Access Token"""

    # URLs
    instance: str = "https://github.com"
    """Instance"""
    api_rest: str = "https://api.github.com"
    """REST API URL"""
    api_graphql: str = "https://api.github.com/graphql"
    """GraphQL API URL"""

    enterprise: Optional[str] = None
    server_version: Optional[Version] = None

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
        if repository:
            GitHub.repository = Repository.parseRepository(repository)
        elif owner and repo:
            GitHub.repository = Repository(owner, repo)

        if GitHub.repository:
            if reference:
                GitHub.repository.reference = reference
            if branch:
                GitHub.repository.branch = branch

        if not token:
            token = os.environ.get("GITHUB_TOKEN")
        GitHub.token = token

        # instance
        if instance:
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
    def getMetaInformation() -> Dict:
        """Get the GitHub Meta Information."""
        from ghastoolkit.octokit.octokit import RestRequest

        response = RestRequest().session.get(f"{GitHub.api_rest}/meta")

        if response.headers.get("X-GitHub-Enterprise-Version"):
            version = response.headers.get("X-GitHub-Enterprise-Version")
            GitHub.server_version = Version(version)

        return response.json()
