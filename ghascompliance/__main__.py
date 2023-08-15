import os
import argparse
import logging

from ghastoolkit.octokit.github import GitHub

from ghascompliance.__version__ import __name__ as tool_name, __banner__, __url__
from ghascompliance.consts import SEVERITIES
from ghascompliance.octokit import Octokit, PullRequest, Summary
from ghascompliance.policy import Policy
from ghascompliance.checks import *

# https://docs.github.com/en/actions/reference/environment-variables#default-environment-variables
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")
GITHUB_OWNER = os.environ.get("GITHUB_OWNER")
GITHUB_EVENT_NAME = os.environ.get("GITHUB_EVENT_NAME")
# GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_REF = os.environ.get("GITHUB_REF")
GITHUB_INSTANCE = os.environ.get("GITHUB_SERVER_URL", "https://github.com")

HERE = os.path.dirname(os.path.realpath(__file__))

parser = argparse.ArgumentParser(tool_name)

parser.add_argument(
    "--debug", action="store_true", default=bool(os.environ.get("DEBUG"))
)
parser.add_argument("--disable-caching", action="store_false")
parser.add_argument("--disable-code-scanning", action="store_true")
parser.add_argument("--disable-dependabot", action="store_true")
parser.add_argument("--disable-dependency-licensing", action="store_true")
parser.add_argument("--disable-dependencies", action="store_true")
parser.add_argument("--disable-secret-scanning", action="store_true")
parser.add_argument("--is-github-app-token", action="store_true", default=False)
parser.add_argument("--is-policy-github-app-token", action="store_true", default=False)
parser.add_argument("--pr-comment", action="store_true", default=False)

github_arguments = parser.add_argument_group("GitHub")
github_arguments.add_argument("--github-token", default=GITHUB_TOKEN)
github_arguments.add_argument("--policy-repo-token")
github_arguments.add_argument("--github-instance", default=GITHUB_INSTANCE)
github_arguments.add_argument("--github-repository", default=GITHUB_REPOSITORY)
# github_arguments.add_argument("--github-event", default=GITHUB_EVENT_PATH)
github_arguments.add_argument("--github-ref", default=GITHUB_REF)
# github_arguments.add_argument("--workflow-event", default=GITHUB_EVENT_NAME)
github_arguments.add_argument("--github-policy")
github_arguments.add_argument("--github-policy-branch", default="main")
github_arguments.add_argument(
    "--github-policy-path",
    default=os.path.join(HERE, "defaults", "policy.yml"),
)

thresholds = parser.add_argument_group("Thresholds")
thresholds.add_argument(
    "--display",
    action="store_true",
    help="Display alerts that violate the threshold",
)
thresholds.add_argument("--action", default="break")
thresholds.add_argument("--severity", default="Error")
thresholds.add_argument("--list-severities", action="store_true")
thresholds.add_argument("--count", type=int, default=-1)


if __name__ == "__main__":
    print(__banner__)
    arguments = parser.parse_args()

    logging.basicConfig(
        filename="ghas-compliant.log",
        level=logging.DEBUG if arguments.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    Octokit.setLevel(logging.DEBUG if arguments.debug else logging.INFO)

    if arguments.debug:
        Octokit.debug("Debugging enabled")

    if GITHUB_EVENT_NAME is not None:
        Octokit.__EVENT__ = True

    if not arguments.github_token:
        raise Exception("Github Access Token required")
    if not arguments.github_repository:
        raise Exception("Github Repository required")

    Summary.addHeader("Policy as Code", 1)
    PullRequest.add_pr_comment = arguments.pr_comment

    GitHub.init(
        arguments.github_repository,
        instance=arguments.github_instance,
        reference=arguments.github_ref,
        token=arguments.github_token,
    )
    GitHub.github_app = arguments.is_github_app_token

    Octokit.info(
        f"GitHub Repository :: {GitHub.repository.owner}/{GitHub.repository.repo}"
    )
    Octokit.info(f"GitHub Instance :: {GitHub.instance}")
    Octokit.info(f"GitHub Reference (branch/pr) :: {GitHub.repository.reference}")

    if arguments.list_severities:
        for severity in SEVERITIES:
            Octokit.info(" -> {}".format(severity))

        exit(0)

    policy_location = None

    Octokit.createGroup("Policy as Code")
    if arguments.github_policy and arguments.github_policy != "":
        # Process [org]/repo
        if "/" in arguments.github_policy:
            policy_location = arguments.github_policy
        else:
            if GITHUB_OWNER is None:
                raise Exception("GitHub Owner/Repo not provided")
            policy_location = GITHUB_OWNER + "/" + arguments.github_policy

        Octokit.info(
            "Loading Policy as Code from Repository - {}/{}/{}".format(
                arguments.github_instance, policy_location, arguments.github_policy_path
            )
        )
    elif arguments.github_policy_path:
        if not os.path.exists(arguments.github_policy_path):
            Octokit.info("Policy config file not present on system, skipping...")
            Octokit.info("File path skipped :: " + str(arguments.github_policy_path))
            arguments.github_policy_path = None
        else:
            Octokit.info(
                "Policy config file set: {}".format(arguments.github_policy_path)
            )

    if arguments.policy_repo_token and arguments.policy_repo_token != "":
        Octokit.debug("Separate policy repo token provided")
        policy_token = arguments.policy_repo_token
        is_policy_app_token = arguments.is_policy_github_app_token
    else:
        Octokit.debug("Using default token for policy repo")
        policy_token = arguments.github_token
        is_policy_app_token = arguments.is_github_app_token

    results = ".compliance"

    # Load policy engine
    policy = Policy(
        severity=arguments.severity,
        repository=policy_location,
        path=arguments.github_policy_path,
        branch=arguments.github_policy_branch,
        token=policy_token,
        isGithubAppToken=is_policy_app_token,
        instance=arguments.github_instance,
    )

    if not policy.name == "":
        Summary.addHeader(f"Policy :: {policy.name}", 4)

    os.makedirs(results, exist_ok=True)
    policy.savePolicy(os.path.join(results, "policy.json"))

    Octokit.info("Finished loading policy")

    if arguments.display and policy.policy:
        Octokit.info("```")
        for plcy, data in policy.policy.items():
            if plcy == "name":
                Octokit.info(f"name: {data}")
            else:
                Octokit.info(
                    "{policy}: '{level}'".format(policy=plcy, level=data.get("level"))
                )

        Octokit.info("```")

    Octokit.endGroup()

    checks = Checks(
        policy,
        debugging=arguments.debug,
        display=arguments.display,
        results_path=results,
        caching=arguments.disable_caching,
    )

    errors = 0

    try:
        if not arguments.disable_code_scanning:
            errors += checks.checkCodeScanning()

        if not arguments.disable_dependabot:
            errors += checks.checkDependabot()

        # Dependency Graph
        if not arguments.disable_dependencies:
            errors += checks.checkDependencies()

        # Dependency Graph Licensing
        if not arguments.disable_dependency_licensing:
            errors += checks.checkDependencyLicensing()

        if not arguments.disable_secret_scanning:
            errors += checks.checkSecretScanning()

    except Exception as err:
        Octokit.error("Unknown Exception was hit, please repo this to " + __url__)
        Octokit.error(str(err))
        Summary.addHeader(f"{Summary.__ICONS__['cross']} :: Error Encountered", 2)
        Summary.addLine(
            f"An unexpected exception was encountered while performing policy checks. Please report this to {__url__}"
        )
        Summary.addLine(Summary.formatItalics(str(err)))

        if arguments.debug:
            raise err
    finally:
        # Summary and PR comment
        Summary.outputJobSummary()
        PullRequest.addPrComment(policy.name)

    Octokit.info("Total unacceptable alerts :: " + str(errors))

    if arguments.action == "break" and errors > 0:
        Octokit.error("Unacceptable Threshold of Risk has been hit!")
        exit(1)
    elif arguments.action == "continue":
        Octokit.info("Skipping threshold break check...")
    elif errors == 0:
        Octokit.info("Acceptable risk and no threshold reached.")
    else:
        Octokit.error("Unknown action type :: " + str(arguments.action))
