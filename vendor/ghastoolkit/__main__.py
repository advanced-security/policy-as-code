"""ghastoolkit main workflow."""

from argparse import Namespace
import logging

from ghastoolkit import __name__ as name, __banner__, __version__
from ghastoolkit.octokit.codescanning import CodeScanning
from ghastoolkit.octokit.dependencygraph import DependencyGraph
from ghastoolkit.octokit.github import GitHub
from ghastoolkit.utils.cli import CommandLine
from ghastoolkit.supplychain.__main__ import (
    runDefault as runSCDefault,
    runOrgAudit as runSCOrgAudit,
)


def header(name: str, width: int = 32):
    logging.info("#" * width)
    logging.info(f"{name:^32}")
    logging.info("#" * width)
    logging.info("")


def runCodeScanning(arguments):
    codescanning = CodeScanning(GitHub.repository)

    alerts = codescanning.getAlerts()

    logging.info(f"Total Alerts :: {len(alerts)}")

    analyses = codescanning.getLatestAnalyses(GitHub.repository.reference)
    logging.info(f"\nTools:")

    for analyse in analyses:
        tool = analyse.get("tool", {}).get("name")
        version = analyse.get("tool", {}).get("version")
        created_at = analyse.get("created_at")

        logging.info(f" - {tool} v{version} ({created_at})")


class MainCli(CommandLine):
    """Main CLI."""

    def arguments(self):
        """Adding additional parsers from submodules."""
        self.addModes(["all"])

    def run(self, arguments: Namespace):
        """Run main CLI."""
        if arguments.version:
            logging.info(f"v{__version__}")
            return

        logging.info(__banner__)

        if arguments.mode in ["all", "codescanning"]:
            logging.info("")
            header("Code Scanning")
            runCodeScanning(arguments)

        if arguments.mode in ["all", "dependencygraph"]:
            logging.info("")
            header("Dependency Graph")
            runSCDefault(arguments)

        if arguments.mode == "org-audit":
            # run org audit with all products
            # supplychain
            runSCOrgAudit(arguments)
            return


if __name__ == "__main__":
    # Arguments
    parser = MainCli(name)

    parser.run(parser.parse_args())
