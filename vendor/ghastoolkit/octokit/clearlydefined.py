import logging
from typing import Any, Optional
from requests import Session

from ghastoolkit.supplychain.dependencies import Dependency


logger = logging.getLogger("ghastoolkit.octokit.clearlydefined")

PROVIDEDERS = {
    "cocoapods": "cocoapods",
    "cratesio": "cratesio",
    "deb": "debian",
    "github": "github",
    "githubactions": "github",
    "gitlab": "gitlab",
    "maven": "mavencentral",
    "npm": "npmjs",
    "nuget": "nuget",
    # packagist,
    "pypi": "pypi",
    "gems": "rubygems",
}


class ClearlyDefined:
    def __init__(self) -> None:
        self.api = "https://api.clearlydefined.io"
        self.session = Session()
        self.session.headers = {"Accept": "*/*"}

    def createCurationUrl(self, dependency: Dependency) -> Optional[str]:
        if not dependency.manager:
            return
        provider = PROVIDEDERS.get(dependency.manager, dependency.manager)

        url = f"{self.api}/curations/{dependency.manager}/{provider}/"
        url += dependency.namespace or "-"
        url += f"/{dependency.name}"
        return url

    def getCurations(self, dependency: Dependency) -> dict[str, Any]:
        if not dependency.manager:
            raise Exception(f"Dependency manager / type must be set")

        url = self.createCurationUrl(dependency)
        if not url:
            logger.warning(f"Url failed to be created from dependency :: {dependency}")
            return {}

        resp = self.session.get(url)
        if resp.status_code != 200:
            raise Exception(f"Failed to access API")

        return resp.json()

    def getLicenses(self, dependency: Dependency) -> list[str]:
        licenses = set()
        try:
            data = self.getCurations(dependency)
            for _, curation in data.get("curations", {}).items():
                curlicense = curation.get("licensed", {}).get("declared")
                if curlicense:
                    licenses.add(curlicense)
        except:
            logger.warning(f"Error getting curation data :: {dependency}")

        return list(licenses)
