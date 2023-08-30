"""CodeQL Packs."""

import os
import json
import glob
import logging
from typing import Any, List, Optional
from semantic_version import Version
import yaml

from ghastoolkit.codeql.cli import CodeQL


logger = logging.getLogger("ghastoolkit.codeql.packs")


class CodeQLPack:
    """CodeQL Pack class."""

    codeql_packages: str = os.path.join(os.path.expanduser("~"), ".codeql", "packages")
    """CodeQL Packages Location"""

    def __init__(
        self,
        path: Optional[str] = None,
        library: Optional[bool] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
        cli: Optional[CodeQL] = None,
    ) -> None:
        """Initialise CodeQL Pack."""
        self.cli = cli or CodeQL()

        self.path = path  # dir
        self.library: bool = library or False
        self.name: str = name or ""
        self.version: str = version or "0.0.0"
        self.dependencies: List["CodeQLPack"] = []

        self.default_suite: Optional[str] = None
        self.warnOnImplicitThis: Optional[bool] = None
        self.dbscheme: Optional[str] = None
        self.extractor: Optional[str] = None
        self.upgrades: Optional[str] = None
        self.groups: Optional[list[str]] = None

        if path:
            # if its a file
            if os.path.isfile(path) and path.endswith("qlpack.yml"):
                path = os.path.realpath(os.path.dirname(path))

            self.path = os.path.realpath(os.path.expanduser(path))

            if os.path.exists(self.qlpack):
                self.load()

        logger.debug(f"Finished loading Pack :: {self}")

    @property
    def qlpack(self) -> str:
        """QL Pack Location."""
        if self.path:
            return os.path.join(self.path, "qlpack.yml")
        return "qlpack.yml"

    def validate(self) -> bool:
        """Validate and check if the path is a valid CodeQL Pack."""
        return os.path.exists(self.qlpack)

    def load(self):
        """Load QLPack file."""
        if not os.path.exists(self.qlpack):
            logger.warning(f"Pack Path :: {self.path}")
            raise Exception(f"Failed to find qlpack file")

        logger.debug(f"Loading Pack from path :: {self.path}")
        with open(self.qlpack, "r") as handle:
            data = yaml.safe_load(handle)

        self.library = bool(data.get("library"))
        self.name = data.get("name", "")
        self.version = data.get("version", "")
        self.default_suite = data.get("defaultSuiteFile")

        self.warnOnImplicitThis = data.get("warnOnImplicitThis")
        self.dbscheme = data.get("dbscheme")
        self.extractor = data.get("extractor")
        self.upgrades = data.get("upgrades")
        self.groups = data.get("groups")

        for name, version in data.get("dependencies", {}).items():
            self.dependencies.append(CodeQLPack(name=name, version=version))

    @staticmethod
    def findByQuery(query_path: str) -> Optional["CodeQLPack"]:
        """Find Pack by query path."""
        stack = query_path.split("/")
        if query_path.startswith("/"):
            stack.insert(0, "/")

        while len(stack) != 0:
            path = os.path.join(*stack, "qlpack.yml")
            if os.path.exists(path):
                return CodeQLPack(path)

            stack.pop(-1)
        return

    def run(self, *args, display: bool = False) -> Optional[str]:
        """Run Pack command."""
        return self.cli.runCommand("pack", *args, display=display)

    def create(self) -> str:
        """Create / Compile a CodeQL Pack."""
        logger.debug(f"Creating CodeQL Pack :: {self.name}")
        home = os.path.expanduser("~")
        packages = os.path.join(home, ".codeql", "packages")
        self.run("create", "--output", packages, self.path)
        return os.path.join(packages, self.name, self.version)

    def publish(self):
        """Publish a CodeQL Pack to a remote registry."""
        self.run("publish", self.path)

    @staticmethod
    def download(name: str, version: Optional[str] = None) -> "CodeQLPack":
        """Download a CodeQL Pack."""
        cli = CodeQL()
        full_name = f"{name}@{version}" if version else name
        logger.debug(f"Download Pack :: {full_name}")

        cli.runCommand("pack", "download", full_name)
        base = os.path.join(CodeQLPack.codeql_packages, name)
        if version:
            return CodeQLPack(os.path.join(base, version))
        else:
            return CodeQLPack(glob.glob(f"{base}/**/")[0])

    def install(self, display: bool = False):
        """Install Dependencies for a CodeQL Pack."""
        self.run("install", self.path, display=display)

    def updateDependencies(self, version: str = "latest"):
        for dep in self.dependencies:
            if version == "latest":
                dep.version = dep.remote_version
        self.updatePack()

    def resolveQueries(self, suite: Optional[str] = None) -> List[str]:
        """Resolve all the queries in a Pack and return them."""
        results = []
        if self.path:
            pack = os.path.join(self.path, suite) if suite else self.path
        else:
            pack = f"{self.name}:{suite}" if suite else self.name

        result = self.cli.runCommand(
            "resolve", "queries", "--format", "bylanguage", pack
        )
        if result:
            for _, queries in json.loads(result).get("byLanguage", {}).items():
                results.extend(list(queries.keys()))
        return results

    @property
    def remote_version(self) -> Optional[str]:
        """Gets the remote version of the pack if possible."""
        from ghastoolkit import CodeScanning

        try:
            cs = CodeScanning()
            latest_remote = cs.getLatestPackVersion(self.name)
            latest_version = (
                latest_remote.get("metadata", {})
                .get("container", {})
                .get("tags", ["NA"])[0]
            )
            return latest_version
        except Exception:
            logging.debug(f"Error getting remote version")
        return None

    def updatePack(self) -> dict[str, Any]:
        """Update Local CodeQL Pack."""
        data = {
            "library": self.library,
            "name": self.name,
            "version": self.version,
            "defaultSuiteFile": self.default_suite,
            "warnOnImplicitThis": self.warnOnImplicitThis,
            "dbscheme": self.dbscheme,
            "extractor": self.extractor,
            "upgrades": self.upgrades,
            "groups": self.groups,
        }
        data = {k: v for k, v in data.items() if v is not None}

        if self.dependencies:
            data["dependencies"] = {}
            for dep in self.dependencies:
                data["dependencies"][dep.name] = dep.version

        if self.path:
            logger.debug(f"Saving pack to path :: {self.path}")
            with open(self.qlpack, "w") as handle:
                yaml.safe_dump(data, handle, sort_keys=False)

        return data

    def updateVersion(self, name: str = "patch", version: Optional[str] = None) -> str:
        """Update CodeQL Pack version."""
        if version:
            self.version = version
            return version

        v = Version(self.version)
        if name == "major":
            v = v.next_major()
        elif name == "minor":
            v = v.next_minor()
        elif name == "patch":
            v = v.next_patch()
        self.version = str(v)
        return self.version

    def __str__(self) -> str:
        """To String."""
        if self.name != "":
            return f"CodeQLPack('{self.name}', '{self.version}')"
        return f"CodeQLPack('{self.path}')"
