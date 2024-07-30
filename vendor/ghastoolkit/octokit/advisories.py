"""GitHub Security Advisories API."""

from typing import Dict, Optional
from ghastoolkit.errors import GHASToolkitError, GHASToolkitTypeError
from ghastoolkit.octokit.github import GitHub, Repository
from ghastoolkit.octokit.octokit import RestRequest
from ghastoolkit.supplychain.advisories import Advisories, Advisory, AdvisoryAffect


class SecurityAdvisories:
    """Security Advisories."""

    def __init__(self, repository: Optional[Repository] = None) -> None:
        """Security Advisories REST API.

        https://docs.github.com/en/rest/security-advisories/repository-advisories
        """
        self.repository = repository or GitHub.repository
        if not self.repository:
            raise Exception("SecurityAdvisories requires Repository to be set")
        self.rest = RestRequest(self.repository)

    def getAdvisories(self) -> Advisories:
        """Get list of security advisories from a repository.

        https://docs.github.com/en/rest/security-advisories/repository-advisories#list-repository-security-advisories
        """
        results = self.rest.get(
            "/repos/{owner}/{repo}/security-advisories", authenticated=True
        )
        if isinstance(results, list):
            advisories = Advisories()
            for advisory in results:
                advisories.append(self.loadAdvisoryData(advisory))
            return advisories

        raise GHASToolkitTypeError(
            f"Error getting advisories from repository",
            docs="https://docs.github.com/en/rest/security-advisories/repository-advisories#list-repository-security-advisories",
        )

    def getAdvisory(self, ghsa_id: str) -> Advisory:
        """Get advisory by ghsa id.

        https://docs.github.com/en/rest/security-advisories/repository-advisories#get-a-repository-security-advisory
        """
        result = self.rest.get(
            "/repos/{owner}/{repo}/security-advisories/{ghsa_id}",
            {"ghsa_id": ghsa_id},
            authenticated=True,
        )
        if isinstance(result, dict):
            return self.loadAdvisoryData(result)

        raise GHASToolkitTypeError(
            f"Error getting advisory by id",
            docs="https://docs.github.com/en/rest/security-advisories/repository-advisories#get-a-repository-security-advisory",
        )

    def createAdvisory(
        self, advisory: Advisory, repository: Optional[Repository] = None
    ):
        """Create a GitHub Security Advisories for a repository.

        https://docs.github.com/en/rest/security-advisories/repository-advisories#create-a-repository-security-advisory
        """
        raise GHASToolkitError("Unsupported feature")

    def createPrivateAdvisory(
        self, advisory: Advisory, repository: Optional[Repository] = None
    ):
        """Create a GitHub Security Advisories for a repository."""
        raise Exception("Unsupported feature")

    def updateAdvisory(
        self, advisory: Advisory, repository: Optional[Repository] = None
    ):
        """Update GitHub Security Advisory.

        https://docs.github.com/en/rest/security-advisories/repository-advisories#update-a-repository-security-advisory
        """
        raise GHASToolkitError("Unsupported feature")

    def loadAdvisoryData(self, data: Dict) -> Advisory:
        """Load Advisory from API data."""
        ghsa_id = data.get("ghsa_id")
        severity = data.get("severity")

        if not ghsa_id or not severity:
            raise Exception("Data is not an advisory")

        aliases = []
        if data.get("cve_id"):
            aliases.append(data.get("cve_id"))

        adv = Advisory(
            ghsa_id,
            severity,
            aliases=aliases,
            summary=data.get("summary", ""),
            cwes=data.get("cwe_ids", []),
        )
        # affected
        for vuln in data.get("vulnerabilities", []):
            introduced = vuln.get("vulnerable_version_range")
            if introduced == "":
                introduced = None
            fixed = vuln.get("patched_versions")
            if fixed == "":
                fixed = None

            affect = AdvisoryAffect(
                ecosystem=vuln.get("package", {}).get("ecosystem", ""),
                package=vuln.get("package", {}).get("name", ""),
                introduced=introduced,
                fixed=fixed,
            )
            adv.affected.append(affect)

        return adv
