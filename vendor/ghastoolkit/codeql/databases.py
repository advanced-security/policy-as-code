from datetime import datetime
from logging import log
import os
import shutil
import zipfile
import tempfile
from typing import *
from dataclasses import dataclass

from yaml import safe_load

from ghastoolkit.codeql.consts import CODEQL_LANGUAGES
from ghastoolkit.octokit.codescanning import CodeScanning, logging
from ghastoolkit.octokit.github import Repository
from ghastoolkit.octokit.octokit import GitHub
from requests import request


logger = logging.getLogger("ghastoolkit.codeql")

__CODEQL_DATABASE_PATHS__ = [
    # local
    os.path.expanduser("~/.codeql/databases"),
    # GitHub Actions
    os.path.join(
        os.environ.get("RUNNER_TEMP", "/home/runner/work/_temp"), "codeql_databases"
    ),
]


@dataclass
class CodeQLDatabase:
    """CodeQL Database Abstraction to make our lives easier"""

    name: str
    """Name"""
    language: str
    """CodeQL Langauge"""
    repository: Optional[Repository] = None
    """GitHub Repository (optional)"""
    path: Optional[str] = None
    """Path to the CodeQL Database"""
    path_download: Optional[str] = None
    """Path to download CodeQL DB if not path is set"""

    loc_baseline: int = 0
    """Lines of Code baseline in DB"""

    created: Optional[datetime] = None
    """Created datetime infomation"""

    def __post_init__(self):
        if self.path:
            if not os.path.exists(self.path):
                raise Exception("Database folder incorrect")
            # TODO: check and load DB data
        else:
            self.path = self.createPath()

        if not self.path_download:
            self.path_download = self.createDownloadPath()

        if self.language not in CODEQL_LANGUAGES:
            raise Exception("Language is not supported by CodeQL Summary Generator")

    def __str__(self) -> str:
        name = str(self.repository) if self.repository else self.name
        if self.created:
            created = self.created.strftime("%Y-%m-%dT%H:%M")
            return f"CodeQLDatabase('{name}', '{self.language}', {created})"
        return f"CodeQLDatabase('{name}', '{self.language}')"

    def __repr__(self) -> str:
        return self.__str__()

    def check(self) -> bool:
        """Check if the current database path is a real CodeQL DB"""
        if self.path and self.exists():
            codeql_db_file = os.path.join(self.path, "codeql-database.yml")
            return os.path.exists(codeql_db_file)
        return False

    def exists(self) -> bool:
        """Checks if the CodeQL Database exists"""
        return False if not self.path else os.path.exists(self.path)

    @property
    def root(self) -> str:
        """Get the standard root location."""
        return __CODEQL_DATABASE_PATHS__[0]

    @property
    def default_pack(self) -> str:
        """Gets the default query pack for language"""
        return f"codeql/{self.language}-queries"

    def getSuite(self, name: str) -> str:
        """Gets suite based on default pack"""
        return f"{self.default_pack}:codeql-suites/{self.language}-{name}.qls"

    def display_name(self, owner: Optional[str] = None) -> str:
        """Get the display name"""
        if self.repository:
            own = self.repository.owner
            repo = self.repository.repo

            if own and own == owner:
                return self.repository.repo.title().replace(" ", "")

            return f"{own.title()}{repo.title()}".replace(" ", "")
        new_name = self.name.replace("-", " ")
        return new_name.title().replace(" ", "")

    def createPath(self) -> Optional[str]:
        """Create a path for CodeQL Database"""
        for root in __CODEQL_DATABASE_PATHS__:
            if not os.path.exists(root):
                continue

            return os.path.join(root, self.database_folder)
        return

    def createDownloadPath(self, root: Optional[str] = None) -> str:
        """Find a path where"""
        if not root:
            root = os.path.join(tempfile.gettempdir(), "codeql-db")
        if self.repository:
            return os.path.join(
                root, self.language, self.repository.owner, self.repository.repo
            )
        return os.path.join(root, self.language, self.name)

    @property
    def database_folder(self) -> str:
        """Get CodeQL Database folder"""
        if self.repository:
            result = f"{self.language}-{self.repository.owner}-{self.repository.repo}"
            if self.repository.sha:
                result += f"-{self.repository.sha}"
        else:
            result = f"{self.name}"

        return result

    @staticmethod
    def loadFromYml(path: str) -> "CodeQLDatabase":
        """Load from YAML / YML file.

        **Example:**
        >>> db = CodeQLDatabase.loadFromYml("codeql-db")

        """
        if not os.path.exists(path):
            raise Exception("CodeQL Database YML does not exist")
        if not path.endswith(".yml"):
            raise Exception("File is not a YML file")
        dirname = os.path.dirname(path)
        name = os.path.basename(dirname)
        db = CodeQLDatabase(name, "python", path=dirname)
        db.loadDatabaseYml(path)
        if db.language == "":
            logger.error(f"CodeQLDatabase Language not set from YML")
            raise Exception(f"Unable to load DB correctly")
        return db

    def loadDatabaseYml(self, path: str):
        """Load content from YML file."""
        if not os.path.exists(path):
            raise Exception("CodeQL Database YML does not exist")
        if not path.endswith(".yml"):
            raise Exception("File is not a YML file")

        with open(path, "r") as handle:
            data = safe_load(handle)

        self.name = os.path.basename(data.get("sourceLocationPrefix", ""))
        self.language = data.get("primaryLanguage")
        self.loc_baseline = data.get("baselineLinesOfCode", 0)

        # can't load datetime with milliseconds...
        creation_time = data.get("creationMetadata", {}).get("creationTime")
        if isinstance(creation_time, datetime):
            self.created = creation_time
        else:
            creation_time, _ = creation_time.split(".", 1)
            self.created = datetime.fromisoformat(creation_time)

    def downloadDatabase(
        self, output: Optional[str] = None, use_cache: bool = True
    ) -> str:
        """Download CodeQL Database."""
        output = output or self.path or self.root
        if not output:
            raise Exception(f"CodeQL Database path not set")

        if not self.language or not self.repository:
            raise Exception(
                f"Database download requires a repository and language to be set"
            )
        codescanning = CodeScanning()
        codeqldb_info = codescanning.getCodeQLDatabase(self.language)

        url = codeqldb_info.get("url")
        if not url:
            raise Exception(f"Remote Database does not exist for `{self.language}`")

        if not os.path.exists(output):
            logger.debug(f"Creating path: {output}")
            os.makedirs(output)

        output_zip = os.path.join(
            tempfile.gettempdir(), self.database_folder + ".tar.gz"
        )
        output_db = os.path.join(tempfile.gettempdir(), self.database_folder)

        # Deleting cached files
        if not use_cache:
            logger.info(f"Deleting cached files...")
            if os.path.exists(output_db):
                shutil.rmtree(output_db)

            if os.path.exists(output_zip):
                os.remove(output_zip)

        if not os.path.exists(output_zip):
            logger.debug("Downloading CodeQL Database from GitHub")

            headers = {
                "Accept": "application/zip",
                "Authorization": f"token {GitHub.token}",
            }

            with request("get", url, headers=headers) as resp:
                with open(output_zip, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=1024):
                        if chunk:
                            f.write(chunk)

        else:
            logger.debug("Database archive is present on system, skipping download...")

        logger.debug(f"Extracting archive data :: {output_zip}")

        # SECURITY: Do we trust this DB?
        with zipfile.ZipFile(output_zip) as zf:
            zf.extractall(output_db)

        logger.debug(f" >>> {output_db}")
        # CodeQL DB is in a folder called `codeql_db` or the language name
        lang_path = os.path.join(output_db, self.language)
        codeql_db_path = (
            lang_path
            if os.path.exists(lang_path)
            else os.path.join(output_db, "codeql_db")
        )

        if os.path.exists(codeql_db_path):
            logger.debug(f"Moving Database...")

            if os.path.exists(output):
                logger.debug(f"Removing old DB :: {output}")
                shutil.rmtree(output)

            shutil.move(codeql_db_path, output)
            self.path = output
            return output

        raise Exception(f"Database downloaded but not DB files...")


class CodeQLDatabases(list[CodeQLDatabase]):
    """List of CodeQL Databases."""

    def loadDefault(self):
        """Load Databases from standard locations."""
        for location in __CODEQL_DATABASE_PATHS__:
            if not os.path.exists(location):
                continue
            self.findDatabases(location)

    @staticmethod
    def loadLocalDatabase() -> "CodeQLDatabases":
        """Load all Local Databases."""
        db = CodeQLDatabases()
        db.loadDefault()
        return db

    def getRemoteDatabases(self, repository: Repository):
        """Find all remote databases and return a list of them."""
        cs = CodeScanning(repository)
        databases = cs.getCodeQLDatabases()
        for db in databases:
            lang = db.get("language")
            if not lang:
                raise Exception(f"CodeQL remote language is not set")
            self.append(
                CodeQLDatabase(repository.repo, language=lang, repository=repository)
            )

    @staticmethod
    def loadRemoteDatabases(repository: Repository) -> "CodeQLDatabases":
        """Use API to find all the databases and return a list of them."""
        dbs = CodeQLDatabases()
        dbs.getRemoteDatabases(repository)
        return dbs

    def findDatabases(self, path: str):
        """Find databases based on a path (recursive)."""
        if not os.path.exists(path):
            raise Exception(f"Path does not exist: {path}")

        for root, _, files in os.walk(path):
            for file in files:
                if file == "codeql-database.yml":
                    path = os.path.join(root, file)
                    self.append(CodeQLDatabase.loadFromYml(path))

    def get(self, name: str) -> Optional[CodeQLDatabase]:
        """Get a database by name."""
        for db in self:
            if db.name == name:
                return db
        return

    def getLanguages(self, language: str) -> "CodeQLDatabases":
        """Get a list of databases by language."""
        dbs = CodeQLDatabases()
        for db in dbs:
            if db.language == language:
                dbs.append(db)
        return dbs

    def downloadDatabases(self):
        """Download all databases from GitHub."""
        for db in self:
            db.downloadDatabase(None)
