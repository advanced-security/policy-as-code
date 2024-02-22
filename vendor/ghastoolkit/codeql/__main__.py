"""CodeQL CLI for ghastoolkit."""

import logging
from argparse import Namespace
from ghastoolkit.codeql.cli import CodeQL
from ghastoolkit.utils.cli import CommandLine


class CodeQLCommandLine(CommandLine):
    """CodeQL CLI."""

    def arguments(self):
        """CodeQL arguments."""
        if self.subparser:
            self.addModes(["init", "analyze", "update"])

            parser = self.parser.add_argument_group("codeql")
            parser.add_argument("-b", "--binary")
            parser.add_argument("-c", "--command", type=str)

    def run(self, arguments: Namespace):
        codeql = CodeQL()

        if not codeql.exists():
            logging.error(f"Failed to find codeql on system")
            exit(1)

        logging.debug(f"Found codeql on system :: '{' '.join(codeql.path_binary)}'")

        if arguments.version:
            logging.info(f"CodeQL Version :: v{codeql.version}")
            exit(0)


if __name__ == "__main__":
    parser = CodeQLCommandLine("ghastoolkit-codeql")
    parser.run(parser.parse_args())
    logging.info(f"Finished!")
