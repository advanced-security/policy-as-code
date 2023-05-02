import os
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse


@dataclass
class Repository:
    owner: str
    repo: str
    reference: Optional[str] = None
    branch: Optional[str] = None

    sha: Optional[str] = None

    def __post_init__(self) -> None:
        if self.reference and not self.branch:
            if not self.isInPullRequest():
                _, _, branch = self.reference.split("/", 2)
                self.branch = branch
        if self.branch and not self.reference:
            self.reference = f"refs/heads/{self.branch}"

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
        if self.reference:
            return int(self.reference.split("/")[2])
        return 0

    @property
    def clone_url(self) -> str:
        if GitHub.github_app:
            url = urlparse(GitHub.instance)
            return f"{url.scheme}://x-access-token:{GitHub.token}@{url.netloc}/{self.owner}/{self.repo}.git"
        elif GitHub.token:
            url = urlparse(GitHub.instance)
            return f"{url.scheme}://{GitHub.token}@{url.netloc}/{self.owner}/{self.repo}.git"
        return f"{GitHub.instance}/{self.owner}/{self.repo}.git"

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

        return

    @staticmethod
    def parseInstance(instance: str) -> Tuple[str, str]:
        url = urlparse(instance)

        # GitHub Cloud (.com)
        if url.netloc == "github.com":
            api = url.scheme + "://api." + url.netloc
            return (api, f"{api}/graphql")
        # GitHub Ent Server
        api = url.scheme + "://" + url.netloc + "/api"

        return (api, f"{api}/graphql")
