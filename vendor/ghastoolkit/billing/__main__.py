"""CodeQL CLI for ghastoolkit."""

import csv
import logging
from argparse import Namespace
from typing import List
from ghastoolkit.octokit.github import GitHub
from ghastoolkit.octokit.enterprise import Organization
from ghastoolkit.octokit.billing import Billing
from ghastoolkit.utils.cli import CommandLine

logger = logging.getLogger("ghastoolkit-billing")


class CostCenter:
    """Cost Center."""

    def __init__(self, name: str, repositories: list[str] = []) -> None:
        """Initialize Cost Center."""
        self.name = name
        self.repositories = set(repositories)

    def addRepository(self, repo: str):
        """Add a Repository."""
        self.repositories.add(repo)


def loadCostCenterCsv(path: str) -> List[CostCenter]:
    cost_centers = {}

    with open(path, "r") as csv_file:
        csv_reader = csv.DictReader(csv_file)

        for row in csv_reader:
            cost_center = row["Cost Center"]
            repo = row["Repository"]

            if cost_centers.get(cost_center):
                cost_centers[cost_center].addRepository(repo)
            else:
                cost_centers[cost_center] = CostCenter(cost_center, [repo])

    return cost_centers.values()


class BillingCommandLine(CommandLine):
    """Billing CLI."""

    def arguments(self):
        """Billing arguments."""
        if self.subparser:
            # self.addModes([""])

            parser = self.parser.add_argument_group("billing")
            parser.add_argument(
                "--csv",
                help="Input CSV Billing File",
            )
            parser.add_argument(
                "--cost-center",
                help="Cost Center CSV File",
            )

    def run(self, arguments: Namespace):
        self.default_logger()

        org = Organization(GitHub.owner)

        if arguments.csv:
            logging.info(f"Loading GHAS Billing from {arguments.csv}")

            ghas = Billing.loadFromCsv(arguments.csv)
        else:
            if GitHub.token is None:
                logger.error("No GitHub Token provided")
                return
            billing = Billing(org)
            ghas = billing.getGhasBilling()

        if not ghas:
            logger.error("No GHAS Billing found")
            return

        print(f"GHAS Active Committers :: {ghas.active}")
        print(f"GHAS Maximum Committers :: {ghas.maximum}")
        print(f"GHAS Purchased Committers :: {ghas.purchased}")

        if arguments.cost_center:
            cost_centers = loadCostCenterCsv(arguments.cost_center)
            print(f"\nCost Centers :: {len(cost_centers)}\n")
            total = 0

            for center in cost_centers:
                active = set()
                repos = 0

                for repo in center.repositories:
                    r = ghas.getRepository(repo, org.name)
                    if r:
                        repos += 1
                        active.update(r.activeCommitterNames())
                    else:
                        logger.warning(f"Repository cost center not found: {repo}")

                print(f" > {center.name} (active: {len(active)}, repos: {repos})")
                total += len(active)

            print(f"\nShared Cost Center Licenses :: {total - ghas.active}")


if __name__ == "__main__":
    parser = BillingCommandLine("ghastoolkit-billing")
    parser.run(parser.parse_args())
    logging.info(f"Finished!")
