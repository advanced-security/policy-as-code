"""This is the CodeQL CLI Module."""
import os
import json
import logging
import tempfile
import subprocess
from typing import List, Optional, Union

from ghastoolkit.codeql.databases import CodeQLDatabase
from ghastoolkit.codeql.results import CodeQLResults


logger = logging.getLogger("ghastoolkit.codeql.cli")


def findCodeQLBinary() -> Optional[List[str]]:
    """Find CodeQL Binary on current system."""
    locations = [["codeql"], ["gh", "codeql"], ["/usr/bin/codeql/codeql"]]

    for location in locations:
        try:
            cmd = location + ["version"]
            with open(os.devnull, "w") as null:
                subprocess.check_call(cmd, stdout=null, stderr=null)

            return location
        except Exception as err:
            logger.debug(f"Failed to find codeql :: {err}")
    return []


class CodeQL:
    """CodeQL CLI."""

    def __init__(self, binary: Optional[str] = None) -> None:
        """Initialise CodeQL CLI Class."""
        if binary:
            self.path_binary = [binary]
        else:
            self.path_binary: Optional[list[str]] = findCodeQLBinary()

    def exists(self) -> bool:
        """Check codeql is present on the system."""
        return self.path_binary != None

    def runCommand(self, *argvs, display: bool = False) -> Optional[str]:
        """Run CodeQL command without the binary / path."""
        logger.debug(f"Running CodeQL Command :: {argvs[0]}...")
        if not self.path_binary:
            raise Exception("CodeQL binary / path was not found")
        cmd = []
        cmd.extend(self.path_binary)
        cmd.extend(argvs)

        if argvs[0] == "database":
            cmd.extend(["--threads", "0", "--ram", "0"])

        if display:
            subprocess.check_output(cmd)
        else:
            result = subprocess.run(cmd, capture_output=True)
            return result.stdout.decode().strip()

    @property
    def version(self) -> str:
        """Get CodeQL Version from the CLI binary."""
        version = self.runCommand("version", "--format", "terse", display=True)
        if not version:
            raise Exception("CodeQL version not found")
        return version

    def runQuery(
        self, database: CodeQLDatabase, path: Optional[str] = None
    ) -> CodeQLResults:
        """Run a CodeQL Query on a CodeQL Database."""
        if not database.path:
            raise Exception("CodeQL Database path is not set")

        path = path or database.default_pack

        self.runCommand("database", "run-queries", database.path, path)
        return self.getResults(database, path)

    def runRawQuery(
        self, path: str, database: CodeQLDatabase, outputtype: str = "bqrs"
    ) -> Union[dict, list]:
        """Run raw query on a CodeQL Database."""
        if not database.path:
            raise Exception("CodeQL Database path is not set")
        if not path.endswith(".ql"):
            raise Exception("runRawQuery requires a QL file")

        self.runCommand("database", "run-queries", database.path, path)
        if outputtype == "bqrs":
            bqrs = os.path.join(
                database.path, "results", path.replace(":", "/").replace(".ql", ".bqrs")
            )
            return self.readBqrs(bqrs)
        return {}

    def getResults(
        self, database: CodeQLDatabase, path: Optional[str] = None
    ) -> CodeQLResults:
        """Get the interpreted results from CodeQL."""
        sarif = os.path.join(tempfile.gettempdir(), "codeql-result.sarif")
        cmd = [
            "database",
            "interpret-results",
            "--format",
            "sarif-latest",
            "--output",
            sarif,
            database.path,
        ]
        if path:
            cmd.append(path)

        self.runCommand(*cmd)

        with open(sarif, "r") as handle:
            data = json.load(handle)

        results = data.get("runs", [])[0].get("results", [])
        return CodeQLResults.loadSarifResults(results)

    def readBqrs(self, bqrsfile: str) -> dict:
        """Read a BQRS file to get the raw results."""
        output = os.path.join(tempfile.gettempdir(), "codeql-result.bqrs")

        self.runCommand(
            "bqrs", "decode", "--format", "json", "--output", output, bqrsfile
        )

        with open(output, "r") as handle:
            return json.load(handle)

    def __str__(self) -> str:
        """To String."""
        if self.path_binary:
            return f"CodeQL('{self.version}')"
        return "CodeQL()"
