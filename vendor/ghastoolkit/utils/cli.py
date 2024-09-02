import logging
import os
from argparse import ArgumentParser, Namespace
from typing import Optional

from ghastoolkit.octokit.github import GitHub


class CommandLine:
    def __init__(
        self,
        name: Optional[str] = None,
        parser: Optional[ArgumentParser] = None,
        default_logger: bool = True,
    ) -> None:
        """Initialize CommandLine."""
        self.parser = parser or ArgumentParser(name or "ghastoolkit")
        self.subparser: bool = parser is None

        if not parser:
            self.default()

        self.modes = set()
        self.modes.add("default")

        self.arguments()

        if not parser:
            self.parser.add_argument(
                "mode",
                const="default",
                nargs="?",
                default="default",
                choices=list(self.modes),
            )

        if default_logger:
            self.default_logger()

    def default(self):
        """Setup default arguments."""
        self.parser.add_argument(
            "--debug", dest="debug", action="store_true", help="Enable Debugging"
        )
        self.parser.add_argument(
            "--version", dest="version", action="store_true", help="Output version"
        )
        self.parser.add_argument(
            "--cwd",
            "--working-directory",
            dest="cwd",
            default=os.getcwd(),
            help="Working directory",
        )

        github = self.parser.add_argument_group("github")

        github.add_argument(
            "-r",
            "--github-repository",
            dest="repository",
            default=os.environ.get("GITHUB_REPOSITORY"),
            help="GitHub Repository (default: GITHUB_REPOSITORY)",
        )
        github.add_argument(
            "--github-instance",
            dest="instance",
            default=os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
            help="GitHub Instance URL (default: GITHUB_SERVER_URL)",
        )
        github.add_argument(
            "--github-owner", dest="owner", help="GitHub Owner (Org/User)"
        )
        github.add_argument(
            "--github-enterprise", dest="enterprise", help="GitHub Enterprise"
        )
        github.add_argument(
            "-t",
            "--github-token",
            dest="token",
            default=os.environ.get("GITHUB_TOKEN"),
            help="GitHub API Token (default: GITHUB_TOKEN)",
        )

        github.add_argument(
            "--sha", default=os.environ.get("GITHUB_SHA"), help="Commit SHA"
        )
        github.add_argument(
            "--ref", default=os.environ.get("GITHUB_REF"), help="Commit ref"
        )

    def addModes(self, modes: list[str]):
        """Set modes."""
        self.modes.update(modes)

    def arguments(self):
        """Set custom arguments."""
        return

    def run(self, arguments: Optional[Namespace] = None):
        """Run CLI."""
        raise Exception("Not implemented")

    def default_logger(self):
        """Setup default logger."""
        arguments = self.parse_args()
        logging.basicConfig(
            level=(
                logging.DEBUG
                if arguments.debug or os.environ.get("DEBUG")
                else logging.INFO
            ),
            format="%(message)s",
        )

    def parse_args(self) -> Namespace:
        """Parse arguments."""
        arguments = self.parser.parse_args()
        # GitHub Init
        GitHub.init(
            repository=arguments.repository,
            reference=arguments.ref,
            owner=arguments.owner,
            instance=arguments.instance,
            token=arguments.token,
            enterprise=arguments.enterprise,
        )

        return arguments
