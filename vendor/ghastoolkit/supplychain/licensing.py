from datetime import datetime
import os
import json
import logging
from typing import Optional, Union

from ghastoolkit.octokit.github import Repository


logger = logging.getLogger("ghastoolkit.supplychain.licenses")

NO_LICENSES = ["None", "NA", "NOASSERTION"]


class Licenses:
    def __init__(self, path: Optional[str] = None) -> None:
        """Licenses"""
        self.data: dict[str, list[str]] = {}
        self.sources: list[str] = []

        if path:
            self.load(path)

    def load(self, path: str):
        """Load a licenses file"""
        if not os.path.exists(path):
            raise Exception(f"License path does not exist: {path}")
        if not os.path.isfile(path):
            raise Exception("Path provided needs to be a file")

        logger.debug(f"Loading licenseing file :: {path}")
        with open(path, "r") as handle:
            data = json.load(handle)
            # TODO validate the data before loading?

        self.data.update(data)

        self.sources.append(path)
        logger.debug(f"Loaded licenses :: {len(self.data)}")

    def add(self, purl: str, licenses: Union[str, list]):
        """Add license"""
        if self.data.get(purl):
            return
        licenses = licenses if isinstance(licenses, list) else [licenses]
        self.data[purl] = licenses

    def find(self, purl: str) -> Optional[list[str]]:
        """Find by PURL"""
        return self.data.get(purl)

    def export(self, path: str):
        """Export licenses file"""
        with open(path, "w") as handle:
            json.dump(self.data, handle)

    def generateLockfile(self, path: str, repository: Optional[Repository] = None):
        """Generate Lockfile for the current licenses"""
        lock_data = {"total": len(self.data), "created": datetime.now().isoformat()}
        if repository:
            lock_data["repository"] = str(repository.display())
            lock_data["version"] = repository.gitsha() or repository.sha

        with open(path, "w") as handle:
            json.dump(lock_data, handle, indent=2, sort_keys=True)

    def __len__(self) -> int:
        return len(self.data)


if __name__ == "__main__":
    import yaml
    import argparse
    from ghastoolkit import Repository, Dependency

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    parser = argparse.ArgumentParser("ghastoolkit.supplychain.licenses")
    parser.add_argument("-o", "--output", help="Output")

    arguments = parser.parse_args()

    logging.info(f"Output :: {arguments.output}")

    licenses = Licenses()

    repository = Repository.parseRepository("clearlydefined/curated-data")
    logging.info(f"Cloning / Using `clearlydefined` repo: {repository.clone_path}")
    repository.clone(clobber=True, depth=1)

    lock_content = {
        "repository": repository.display(),
        "version": repository.gitsha(),
    }

    # https://github.com/clearlydefined/curated-data/tree/master/curations
    curations = repository.getFile("curations")

    for root, dirs, files in os.walk(curations):
        for filename in files:
            name, ext = os.path.splitext(filename)
            if ext not in [".yml", ".yaml"]:
                continue

            path = os.path.join(root, filename)

            with open(path, "r") as handle:
                curation_data = yaml.safe_load(handle)

            coordinates = curation_data.get("coordinates", {})
            purl = Dependency(
                coordinates.get("name"),
                coordinates.get("namespace"),
                manager=coordinates.get("type"),
            ).getPurl()

            revision_licenses = set()
            for _, revision in curation_data.get("revisions", {}).items():
                l = revision.get("licensed")
                if l and l.get("declaired"):
                    revision_licenses.add(l.get("declaired"))

            licenses.add(purl, list(revision_licenses))

    logging.info(f"Licenses Loaded :: {len(licenses)}")

    # lock
    lock_path = arguments.output.replace(".json", ".lock.json")
    logging.info(f"Saving lock file :: {lock_path}")
    licenses.generateLockfile(lock_path, repository=repository)

    # export
    logging.info(f"Exporting Output :: {arguments.output}")
    licenses.export(arguments.output)
