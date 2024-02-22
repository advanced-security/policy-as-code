"""Supply Chain Toolkit CLI."""

from argparse import Namespace
import logging

from ghastoolkit.octokit.dependencygraph import DependencyGraph
from ghastoolkit.octokit.github import GitHub
from ghastoolkit.utils.cli import CommandLine


def runDefault(arguments):
    depgraph = DependencyGraph(GitHub.repository)
    bom = depgraph.exportBOM()
    packages = bom.get("sbom", {}).get("packages", [])

    logging.info(f"Total Dependencies :: {len(packages)}")

    info = bom.get("sbom", {}).get("creationInfo", {})
    logging.info(f"SBOM Created :: {info.get('created')}")

    logging.info("\nTools:")
    for tool in info.get("creators", []):
        logging.info(f" - {tool}")


def runOrgAudit(arguments):
    """Run an audit on an organization."""
    licenses = arguments.licenses.split(",")
    logging.info(f"Licenses :: {','.join(licenses)}")

    if arguments.debug:
        logging.getLogger("ghastoolkit.octokit.dependencygraph").setLevel(logging.DEBUG)

    depgraph = DependencyGraph()

    dependencies = depgraph.getOrganizationDependencies()

    for repo, deps in dependencies.items():
        # get a list of deps that match the licenses
        violations = deps.findLicenses(licenses)
        # get a list of deps with no license data
        unknowns = deps.findUnknownLicenses()

        if len(violations) == 0 and len(unknowns) == 0:
            continue

        logging.info(f" > {repo} :: {len(deps)}")
        logging.info(f" |-> Unknowns   :: {len(unknowns)}")
        for unknown in unknowns:
            logging.warning(f" |---> {unknown.getPurl()}")

        logging.info(f" |-> Violations :: {len(violations)}")
        for violation in violations:
            logging.warning(f" |---> {violation.getPurl()}")


class SupplyChainCLI(CommandLine):
    def arguments(self):
        """CLI for Supply Chain Toolkit."""
        if self.subparser:
            self.addModes(["org-audit"])

            parser = self.parser.add_argument_group("supplychain")
            parser.add_argument(
                "--licenses",
                default="GPL-*,AGPL-*,LGPL-*",
                help="License(s) to check for (default: 'GPL-*,AGPL-*,LGPL-*')",
            )

    def run(self, arguments: Namespace):
        """Run Supply Chain Toolkit."""
        if arguments.mode == "default":
            runDefault(arguments)
        elif arguments.mode == "org-audit":
            runOrgAudit(arguments)
        else:
            self.parser.print_help()
            exit(1)


if __name__ == "__main__":
    parser = SupplyChainCLI()
    parser.run(parser.parse_args())
    logging.info("Done.")
