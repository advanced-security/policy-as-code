import os
import json
import logging
from typing import Optional


logger = logging.getLogger("ghastoolkit.supplychain.licenses")


class Licenses:
    data: dict[str, list[str]] = {}

    def __init__(self, path: Optional[str] = None) -> None:
        if path:
            self.load(path)

    def load(self, path: str):
        if not os.path.exists(path):
            raise Exception(f"License path does not exist: {path}")
        if not os.path.isfile(path):
            raise Exception("Path provided needs to be a file")

        logger.debug(f"Loading licenseing file :: {path}")
        with open(path, "r") as handle:
            data = json.load(handle)

        Licenses.data = data
        logger.debug(f"Loaded licenses :: {len(data)}")

    def add(self, purl: str, licenses: str | list):
        """Add license"""
        if Licenses.data.get(purl):
            return
        licenses = licenses if isinstance(licenses, list) else [licenses]
        Licenses.data[purl] = licenses

    def find(self, purl: str) -> Optional[list[str]]:
        """Find by PURL"""
        return Licenses.data.get(purl)

    def export(self, path: str):
        with open(path, "w") as handle:
            json.dump(Licenses.data, handle)

    def __len__(self) -> int:
        return len(self.data)


if __name__ == "__main__":
    import yaml
    import argparse
    from ghastoolkit.octokit.github import Repository

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
            purl = f"pkg:{coordinates.get('type')}/{coordinates.get('namespace')}/{coordinates.get('name')}"

            revision_licenses = set()
            for _, revision in curation_data.get("revisions", {}).items():
                l = revision.get("licensed")
                if l and l.get("declaired"):
                    revision_licenses.add(l.get("declaired"))

            licenses.add(purl, list(revision_licenses))

    logging.info(f"Licenses Loaded :: {len(licenses)}")

    # lock file
    lock_path = arguments.output.replace(".json", ".lock.json")
    logging.info(f"Saving lock file :: {lock_path}")
    with open(lock_path, "w") as handle:
        json.dump(lock_content, handle, sort_keys=True, indent=2)

    licenses.export(arguments.output)
