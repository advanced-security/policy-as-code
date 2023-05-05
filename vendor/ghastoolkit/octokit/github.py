import logging
import os
import shutil
import tempfile
import subprocess
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse


logger = logging.getLogger("ghastoolkit.octokit.github")


@dataclass
class Repository:
    owner: str
    repo: str

    reference: Optional[str] = None
    branch: Optional[str] = None
    __prinfo__: Optional[dict] = None

    sha: Optional[str] = None

    clone_path: Optional[str] = None

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
        name = f"{self.owner}/{self.repo}"
        if self.reference:
            return f"{name}:{self.reference}"
        elif self.branch:
            return f"{name}@{self.branch}"
        return name

    def __repr__(self) -> str:
        return self.__str__()

    def isInPullRequest(self) -> bool:
        """Is in Pull Request?"""
        if self.reference:
            return self.reference.startswith("refs/pull")
        return False

    def getPullRequestNumber(self) -> int:
        """Get Pull Request Number"""
        if self.isInPullRequest() and self.reference:
            return int(self.reference.split("/")[2])
        return 0

    def getPullRequestInfo(self) -> dict:
        """Get information for the current pull request

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
        """Get Pull Request Commits"""
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

    @property
    def clone_url(self) -> str:
        if GitHub.github_app:
            url = urlparse(GitHub.instance)
            return f"{url.scheme}://x-access-token:{GitHub.token}@{url.netloc}/{self.owner}/{self.repo}.git"
        elif GitHub.token:
            url = urlparse(GitHub.instance)
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
        """Clone Repository
        The clone path if left None will create a tmp folder for you
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
        cmd = ["git", "rev-parse", "HEAD"]
        result = (
            subprocess.check_output(cmd, cwd=self.clone_path).decode("ascii").strip()
        )
        return result

    def getFile(self, path: str) -> str:
        """Get a path relative from the base of the cloned repository"""
        if not self.clone_path:
            raise Exception(f"Unknown clone path")
        return os.path.join(self.clone_path, path)

    def display(self):
        if self.reference:
            return f"{self.owner}/{self.repo}@{self.reference}"
        return f"{self.owner}/{self.repo}"

    @staticmethod
    def parseRepository(name: str) -> "Repository":
        ref = None
        branch = None
        if "@" in name:
            name, branch = name.split("@", 1)
            ref = f"refs/heads/{branch}"

        owner, repo = name.split("/", 1)
        return Repository(owner, repo, reference=ref, branch=branch)


class GitHub:
    repository: Repository = Repository("GeekMasher", "ghastoolkit")
    token: Optional[str] = None

    # URLs
    instance: str = "https://github.com"
    api_rest: str = "https://api.github.com"
    api_graphql: str = "https://api.github.com/graphql"

    enterprise: Optional[str] = None

    github_app: bool = False

    @staticmethod
    def init(
        repository: Optional[str] = None,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        reference: Optional[str] = None,
        branch: Optional[str] = None,
        token: Optional[str] = os.environ.get("GITHUB_TOKEN"),
        instance: Optional[str] = None,
        enterprise: Optional[str] = None,
    ) -> None:
        if repository:
            GitHub.repository = Repository.parseRepository(repository)
        elif owner and repo:
            GitHub.repository = Repository(owner, repo)

        if GitHub.repository:
            if reference:
                GitHub.repository.reference = reference
            if branch:
                GitHub.repository.branch = branch

        GitHub.token = token
        # instance
        if instance:
            GitHub.instance = instance
            GitHub.api_rest, GitHub.api_graphql = GitHub.parseInstance(instance)

        GitHub.enterprise = enterprise

        return

    @staticmethod
    def parseInstance(instance: str) -> Tuple[str, str]:
        """Parse GitHub Instance"""
        url = urlparse(instance)

        # GitHub Cloud (.com)
        if url.netloc == "github.com":
            api = url.scheme + "://api." + url.netloc
            return (api, f"{api}/graphql")
        # GitHub Ent Server
        api = url.scheme + "://" + url.netloc + "/api/v3"

        return (api, f"{api}/graphql")

    @staticmethod
    def display() -> str:
        return f"GitHub('{GitHub.repository.display()}', '{GitHub.instance}')"
