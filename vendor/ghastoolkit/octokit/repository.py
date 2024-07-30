import os
import re
import shutil
import logging
import tempfile
import subprocess
from dataclasses import dataclass
from typing import Optional, Union
from urllib.parse import urlparse

from ghastoolkit.errors import GHASToolkitError


logger = logging.getLogger("ghastoolkit.octokit.repository")


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

    path: Optional[str] = None
    """Path inside the repository"""

    pr_number: Optional[int] = None
    """Pull Request Number (if in a PR)"""

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

            self.pr_number = self.getPullRequestNumber()
            self.__prinfo__ = RestRequest().get(
                "/repos/{owner}/{repo}/pulls/{pull_number}",
                {"pull_number": self.pr_number},
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
        from ghastoolkit.octokit.github import GitHub

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
            raise GHASToolkitError(f"Unknown clone path")
        return os.path.join(self.clone_path, path)

    def display(self) -> str:
        """Display the repository as a string."""
        if self.reference:
            return f"{self.owner}/{self.repo}@{self.reference}"
        return f"{self.owner}/{self.repo}"

    @staticmethod
    def parseRepository(name: str) -> "Repository":
        """Parse the repository name into a Repository object.

        Samples:
            - owner/repo
            - owner/repo@branch
            - owner/repo:relative/path/in/repo
            - owner/repo/relative/path/in/repo
            - owner/repo:relative/path/in/repo@branch
        """
        ref = None
        branch = None
        path = None

        # validate the repository name
        regex = re.compile(
            r"^[a-zA-Z0-9-_\.]+/[a-zA-Z0-9-_\.]+((:|/)[a-zA-Z0-9-_/\.]+)?(@[a-zA-Z0-9-_/]+)?$"
        )
        if not regex.match(name):
            raise SyntaxError(f"Invalid repository name: '{name}'")

        if "@" in name:
            name, branch = name.split("@", 1)
            ref = f"refs/heads/{branch}"
        if ":" in name:
            name, path = name.split(":", 1)
        if name.count("/") > 1:
            owner, repo, path = name.split("/", 2)
        else:
            owner, repo = name.split("/", 1)
        return Repository(owner, repo, reference=ref, branch=branch, path=path)
