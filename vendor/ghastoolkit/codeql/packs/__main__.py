"""GitHub CodeQL Packs CLI."""

import os
import logging
from argparse import Namespace
from typing import Optional

from yaml import parse
from ghastoolkit.codeql.packs.packs import CodeQLPacks
from ghastoolkit.utils.cli import CommandLine


def codeqlPackPublish(arguments: Namespace, packs: CodeQLPacks):
    if not arguments.packs or arguments.packs == "":
        logging.error(f"CodeQL Pack path must be provided")
        exit(1)

    for pack in packs:
        remote = pack.remote_version
        logging.info(f"CodeQL Pack Remote Version :: {remote}")

        if pack.version != remote:
            logging.info("Publishing CodeQL Pack...")
            pack.publish()
            logging.info(f"CodeQL Pack published :: {pack}")
        else:
            logging.info(f"CodeQL Pack is up to date :: {pack}")


class CodeQLPacksCommandLine(CommandLine):
    def arguments(self):
        self.addModes(["publish", "queries", "compile", "version"])
        default_pack_path = os.path.expanduser("~/.codeql/packages")

        parser = self.parser.add_argument_group("codeql-packs")
        parser.add_argument(
            "--packs",
            type=str,
            default=os.environ.get("CODEQL_PACKS_PATH", default_pack_path),
            help="CodeQL Packs Path",
        )
        parser.add_argument(
            "--bump",
            type=str,
            default="patch",
            help="CodeQL Pack Version Bump",
        )
        parser.add_argument(
            "--suite",
            type=str,
            default="default",
            help="CodeQL Pack Suite",
        )
        parser.add_argument(
            "--latest",
            action="store_true",
            help="Update to latest CodeQL Pack Dependencies",
        )
        parser.add_argument("--warnings", action="store_true", help="Enable Warnings")

    def run(self, arguments: Optional[Namespace] = None):
        if not arguments:
            arguments = self.parse_args()

        logging.info(f"CodeQL Packs Path :: {arguments.packs}")
        packs = CodeQLPacks(arguments.packs)

        if arguments.latest:
            logging.info("Updating CodeQL Pack Dependencies...")
            for pack in packs:
                pack.updateDependencies()

        if arguments.mode == "publish":
            codeqlPackPublish(arguments, packs)

        elif arguments.mode == "version":
            logging.info(f"Loading packs from :: {arguments.packs}")

            for pack in packs:
                old_version = pack.version
                pack.updateVersion(arguments.bump)
                pack.updatePack()
                logging.info(
                    f"CodeQL Pack :: {pack.name} :: {old_version} -> {pack.version}"
                )

        elif arguments.mode == "queries":
            suite = arguments.suite or "code-scanning"
            for pack in packs:
                logging.info(f"CodeQL Pack :: {pack}")

                if not pack.library:
                    if suite == "default" and pack.default_suite:
                        suite = pack.default_suite

                    queries = pack.resolveQueries(suite)
                    logging.info(f"Queries: {len(queries)}")
                    for query in queries:
                        logging.info(f"- {query}")

        elif arguments.mode == "compile":
            for pack in packs:
                logging.info(f"CodeQL Pack :: {pack}")

        else:
            logging.info("CodeQL Packs")
            for pack in packs:
                logging.info(f"- {pack}")

                for dep in pack.dependencies:
                    logging.info(f" |-> {dep}")


if __name__ == "__main__":
    parser = CodeQLPacksCommandLine("ghastoolkit-codeql-packs")
    parser.run(parser.parse_args())
    logging.info(f"Finished!")
