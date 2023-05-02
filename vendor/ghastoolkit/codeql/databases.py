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


__CODEQL_DATABASE_PATHS__ = [os.path.expanduser("~/.codeql/databases")]

logger = logging.getLogger("ghastoolkit.codeql")


@dataclass
class CodeQLDatabase:
    name: str
    language: str
    repository: Optional[Repository] = None

    # path to when the DB should be
    path: Optional[str] = None
    path_download: Optional[str] = None

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
        return False if not self.path else os.path.exists(self.path)

    def display_name(self, owner: Optional[str] = None) -> str:
        """Display Name"""
        if self.repository:
            own = self.repository.owner
            repo = self.repository.repo

            if own and own == owner:
                return self.repository.repo.title().replace(" ", "")

            return f"{own.title()}{repo.title()}".replace(" ", "")
        new_name = self.name.replace("-", " ")
        return new_name.title().replace(" ", "")

    def createPath(self) -> Optional[str]:
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
        if self.repository:
            result = f"{self.language}-{self.repository.owner}-{self.repository.repo}"
            if self.repository.sha:
                result += f"-{self.repository.sha}"
        else:
            result = f"{self.name}"

        return result

    @staticmethod
    def loadDatabaseYml(path: str) -> "CodeQLDatabase":
        if not os.path.exists(path):
            raise Exception("CodeQL Database YML does not exist")
        if not path.endswith(".yml"):
            raise Exception("File is not a YML file")

        name = os.path.basename(os.path.dirname(path))

        with open(path, "r") as handle:
            data = safe_load(handle)

        db = CodeQLDatabase(name, data.get("primaryLanguage"), path=path)
        return db

    def downloadDatabase(self, output: Optional[str], use_cache: bool = True) -> str:
        """Download CodeQL database"""
        output = output or self.path or self.path_download
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

        output_zip = os.path.join(output, self.database_folder + ".tar.gz")
        output_db = os.path.join(output, self.database_folder)

        # Deleting cached files
        if not use_cache:
            logger.info(f"Deleting cached files...")
            if os.path.exists(output_db):
                shutil.rmtree(output_db)

            if os.path.exists(output_zip):
                os.remove(output_zip)

        if not os.path.exists(output_zip):
            logger.info("Downloading CodeQL Database from GitHub")

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
            logger.info("Database archive is present on system, skipping download...")

        logger.info(f"Extracting archive data :: {output_zip}")

        # SECURITY: Do we trust this DB?
        with zipfile.ZipFile(output_zip) as zf:
            zf.extractall(output_db)

        logger.info(f" >>> {output_db}")
        codeql_lang_path = os.path.join(output_db, self.language)

        if os.path.exists(codeql_lang_path):
            return codeql_lang_path

        for codeql_dir in os.listdir(output_db):
            codeql_dir = os.path.join(output_db, codeql_dir)
            if os.path.isdir(codeql_dir):
                return codeql_dir

        raise Exception(f"Database downloaded but not DB files...")


class CodeQLDatabases(list[CodeQLDatabase]):
    def loadDefault(self):
        """Load Databases from standard locations"""
        for location in __CODEQL_DATABASE_PATHS__:
            if not os.path.exists(location):
                continue
            self.findDatabases(location)

    @staticmethod
    def loadLocalDatabase() -> "CodeQLDatabases":
        """Load all Local Databases"""
        db = CodeQLDatabases()
        db.loadDefault()
        return db

    def getRemoteDatabases(self, repository: Repository):
        """Find all remote databases and return a list of them"""
        cs = CodeScanning(repository)
        databases = cs.getCodeQLDatabases()
        for db in databases:
            lang = db.get("language")
            if not lang:
                raise Exception(f"CodeQL remote language is not set")
            self.append(
                CodeQLDatabase(
                    f"{repository.repo}-{lang}", language=lang, repository=repository
                )
            )

    @staticmethod
    def loadRemoteDatabases(repository: Repository) -> "CodeQLDatabases":
        """Use API to find all the databases and return a list of them"""
        dbs = CodeQLDatabases()
        dbs.getRemoteDatabases(repository)
        return dbs

    def findDatabases(self, path: str):
        if not os.path.exists(path):
            raise Exception(f"Path does not exist: {path}")

        for root, _, files in os.walk(path):
            for file in files:
                if file == "codeql-database.yml":
                    path = os.path.join(root, file)
                    self.append(CodeQLDatabase.loadDatabaseYml(path))

    def downloadDatabases(self):
        for db in self:
            db.downloadDatabase(None)
