"""GitHub CodeQL Packs CLI."""
import os
import logging
from argparse import Namespace
from typing import Optional
from ghastoolkit.codeql.packs.packs import CodeQLPacks
from ghastoolkit.utils.cli import CommandLine


def codeqlPackPublish(arguments: Namespace):
    if not arguments.packs or arguments.packs == "":
        logging.error(f"CodeQL Pack path must be provided")
        exit(1)

    packs = CodeQLPacks(arguments.packs)

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
        self.addModes(["publish"])

        parser = self.parser.add_argument_group("codeql-packs")
        parser.add_argument(
            "--packs",
            type=str,
            default=os.path.expanduser("~/.codeql/packages"),
            help="CodeQL Packs Path",
        )
        parser.add_argument(
            "--bump",
            type=str,
            default="patch",
            help="CodeQL Pack Version Bump",
        )

    def run(self, arguments: Optional[Namespace] = None):
        if not arguments:
            arguments = self.parse_args()

        if arguments.mode == "publish":
            codeqlPackPublish(arguments)

        else:
            # list packs
            logging.info(f"Loading packs from :: {arguments.packs}")
            packs = CodeQLPacks(arguments.packs)
            for pack in packs:
                logging.info(f"CodeQL Pack :: {pack}")


if __name__ == "__main__":
    parser = CodeQLPacksCommandLine("ghastoolkit-codeql-packs")
    parser.run(parser.parse_args())
    logging.info(f"Finished!")
