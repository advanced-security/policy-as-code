import json
import os
import logging
import argparse

from ghastoolkit import __name__ as name, __banner__
from ghastoolkit.octokit.github import GitHub
from ghastoolkit.octokit.codescanning import CodeScanning
from ghastoolkit.octokit.dependencygraph import (
    DependencyGraph,
)

# Arguments
parser = argparse.ArgumentParser(name)
parser.add_argument("--debug", action="store_true")

parser.add_argument(
    "mode", choices=["all", "codescanning", "codeql", "dependencygraph"]
)

parser.add_argument("-sha", default=os.environ.get("GITHUB_SHA"), help="Commit SHA")
parser.add_argument("-ref", default=os.environ.get("GITHUB_REF"), help="Commit ref")

parser_github = parser.add_argument_group("GitHub")
parser_github.add_argument(
    "-r",
    "--github-repository",
    default=os.environ.get("GITHUB_REPOSITORY"),
    help="GitHub Repository",
)
parser_github.add_argument(
    "--github-instance",
    default=os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
    help="GitHub Instance",
)
parser_github.add_argument(
    "-t",
    "--github-token",
    default=os.environ.get("GITHUB_TOKEN"),
    help="GitHub API Token",
)

arguments = parser.parse_args()


def header(name: str):
    print("#" * 32)
    print(f"    {name}")
    print("#" * 32)
    print("")


# logger
logging.basicConfig(
    level=logging.DEBUG if arguments.debug or os.environ.get("DEBUG") else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

print(__banner__)

# GitHub Init
GitHub.init(
    repository=arguments.github_repository,
    instance=arguments.github_instance,
    token=arguments.github_token,
)

if not GitHub.repository:
    raise Exception(f"GitHub Repository must be set")

if arguments.mode in ["all", "codescanning"]:
    header("Code Scanning")
    codescanning = CodeScanning(GitHub.repository)

    alerts = codescanning.getAlerts()

    print(f"Total Alerts :: {len(alerts)}")

    analyses = codescanning.getLatestAnalyses(GitHub.repository.reference)
    print(f"\nTools:   ({len(analyses)})")

    for analyse in analyses:
        tool = analyse.get("tool", {}).get("name")
        version = analyse.get("tool", {}).get("version")
        created_at = analyse.get("created_at")

        print(f" - {tool} v{version} ({created_at})")


if arguments.mode in ["all", "dependencygraph"]:
    header("Dependency Graph")

    depgraph = DependencyGraph(GitHub.repository)
    bom = depgraph.exportBOM()
    packages = bom.get("sbom", {}).get("packages", [])

    print(f"Total Dependencies :: {len(packages)}")

    info = bom.get("sbom", {}).get("creationInfo", {})
    print(f"Created :: {info.get('created')}")

    print("\nTools:")
    for tool in info.get("creators", []):
        print(f" - {tool}")
