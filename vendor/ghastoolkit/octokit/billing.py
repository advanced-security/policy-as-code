import logging
import csv
from dataclasses import dataclass, field
from typing import Optional, List, Set

from ghastoolkit.errors import GHASToolkitError
from ghastoolkit.octokit.github import GitHub
from ghastoolkit.octokit.octokit import RestRequest, OctoItem, loadOctoItem
from ghastoolkit.octokit.enterprise import Organization


logger = logging.getLogger("ghastoolkit.octokit.github")


@dataclass
class BillingUser(OctoItem):
    """Billing User."""

    user_login: str
    """Login."""
    last_pushed_date: str
    """Last Pushed Date."""
    last_pushed_email: str
    """Last Pushed Email."""

    @property
    def login(self) -> str:
        """Login."""
        return self.user_login


@dataclass
class BillingRepository(OctoItem):
    """Billing Repository."""

    name: str
    """Repository Name."""
    advanced_security_committers: int
    """Advanced Security Committers."""
    advanced_security_committers_breakdown: List[BillingUser] = field(
        default_factory=list
    )
    """Advanced Security Committers Breakdown."""

    def activeCommitterCount(self) -> int:
        """Count of Active Committers."""
        return len(self.advanced_security_committers_breakdown)

    def activeCommitterNames(self) -> Set[str]:
        """Active Committer Names."""
        results = set()
        for commiter in self.advanced_security_committers_breakdown:
            results.add(commiter.login)
        return results

    def activeCommitterEmails(self) -> Set[str]:
        """Active Committer Emails."""
        results = set()
        for commiter in self.advanced_security_committers_breakdown:
            results.add(commiter.last_pushed_email)
        return results


@dataclass
class GhasBilling(OctoItem):
    """Billing Response."""

    repositories: List[BillingRepository] = field(default_factory=list)
    """Repositories (required)."""

    total_advanced_security_committers: Optional[int] = None
    """Total Advanced Security Committers."""
    total_count: Optional[int] = None
    """Total Count."""
    maximum_advanced_security_committers: Optional[int] = None
    """Maximum Advanced Security Committers."""
    purchased_advanced_security_committers: Optional[int] = None
    """Purchased Advanced Security Committers."""

    @property
    def active(self) -> int:
        """Active Advanced Security Committers."""
        return self.total_advanced_security_committers or 0

    @property
    def maximum(self) -> int:
        """Maximum Advanced Security Committers."""
        return self.maximum_advanced_security_committers or 0

    @property
    def purchased(self) -> int:
        """Purchased Advanced Security Committers."""
        return self.purchased_advanced_security_committers or 0

    def getRepository(
        self, name: str, org: Optional[str] = None
    ) -> Optional[BillingRepository]:
        """Get Repository by Name."""
        for repo in self.repositories:
            org, repo_name = repo.name.split("/", 1)
            if repo_name == name:
                return repo

        return None

    def activeCommitterNames(self) -> Set[str]:
        """Active Committer Names."""
        results = set()
        for repo in self.repositories:
            results.update(repo.activeCommitterNames())
        return results

    def activeCommitterEmails(self) -> Set[str]:
        """Active Committer Emails."""
        results = set()
        for repo in self.repositories:
            results.update(repo.activeCommitterEmails())
        return results


class Billing:
    """GitHub Billing API"""

    def __init__(self, organization: Optional[Organization] = None) -> None:
        """Initialise Billing API."""
        if organization is not None:
            self.org = organization.name
        else:
            self.org = GitHub.owner
        self.rest = RestRequest()
        self.state = None

    def getGhasBilling(self) -> GhasBilling:
        """Get GitHub Advanced Security Billing."""
        if self.org is None:
            logger.error("No organization provided")
            raise GHASToolkitError(
                "No organization provided",
            )
        result = self.rest.get(f"/orgs/{self.org}/settings/billing/advanced-security")

        if isinstance(result, dict):
            return loadOctoItem(GhasBilling, result)

        logger.error("Error getting billing")
        raise GHASToolkitError(
            "Error getting billing",
            permissions=['"Administration" organization permissions (read)'],
            docs="https://docs.github.com/en/enterprise-cloud@latest/rest/billing/billing#get-github-advanced-security-active-committers-for-an-organization",
        )

    @staticmethod
    def loadFromCsv(path: str) -> GhasBilling:
        """Load Billing from CSV."""
        # name: {
        repositories: dict[str, List[BillingUser]] = {}
        unique_committers = []

        with open(path, mode="r") as csv_file:
            csv_reader = csv.DictReader(csv_file)

            for row in csv_reader:
                repo = row["Organization / repository"]
                # if exists, add user to list
                user = BillingUser(
                    row["User login"],
                    row["Last pushed date"],
                    row["Last pushed email"],
                )
                if repositories.get(repo):
                    repositories[repo].append(user)
                else:
                    repositories[repo] = [user]

                if user.login not in unique_committers:
                    unique_committers.append(user.login)

        result = GhasBilling([])
        result.total_count = len(unique_committers)
        result.total_advanced_security_committers = len(unique_committers)

        for repo, usrs in repositories.items():
            result.repositories.append(BillingRepository(repo, len(usrs), usrs))

        return result
