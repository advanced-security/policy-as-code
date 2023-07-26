import os
import argparse
import logging
from typing import Optional

from ghastoolkit.octokit.github import GitHub

from ghascompliance import Octokit, __name__ as tool_name, __banner__, __url__
from ghascompliance.policies import PolicyEngine
from vendor.ghastoolkit.octokit.github import Repository


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
parser.add_argument("--is-github-app-token", action="store_true", default=False)

github_arguments = parser.add_argument_group("GitHub")
github_arguments.add_argument("--github-token", default=GITHUB_TOKEN)
github_arguments.add_argument("--github-instance", default=GITHUB_INSTANCE)
github_arguments.add_argument("--github-repository", default=GITHUB_REPOSITORY)
github_arguments.add_argument("--github-ref", default=GITHUB_REF)

policy_arguments = parser.add_argument_group("Policy")
github_arguments.add_argument(
    "--github-policy", default=os.environ.get("GITHUB_POLICY")
)
github_arguments.add_argument("--github-policy-branch", default="main")
github_arguments.add_argument(
    "--github-policy-path",
    default=os.environ.get(
        "GITHUB_POLICY_PATH", os.path.join(HERE, "defaults", "policy.yml")
    ),
)

thresholds = parser.add_argument_group("Thresholds")
thresholds.add_argument("--action", default="break")
thresholds.add_argument("--count", type=int, default=-1)


if __name__ == "__main__":
    print(__banner__)
    arguments = parser.parse_args()

    logging.basicConfig(
        filename="ghas-compliant.log",
        level=logging.DEBUG if arguments.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if arguments.debug:
        Octokit.logger.level = logging.DEBUG
        Octokit.debug("Debugging enabled")

    if not arguments.github_token:
        raise Exception("Github Access Token required")
    if not arguments.github_repository:
        raise Exception("Github Repository required")

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
    Octokit.info(f"GitHub Instance   :: {GitHub.instance}")
    Octokit.info(
        f"GitHub Reference  :: {GitHub.repository.reference} (PR: {GitHub.repository.isInPullRequest()})"
    )
    Octokit.debug(f"GitHub App :: {GitHub.github_app}")

    #
    policy_location: Optional[Repository] = None

    Octokit.createGroup("Policy as Code")
    if arguments.github_policy and arguments.github_policy != "":
        # Process [org]/repo
        if "/" in arguments.github_policy:
            policy_location = Repository.parseRepository(arguments.github_policy)
        else:
            if GITHUB_OWNER is None:
                raise Exception("GitHub Owner/Repo not provided")
            policy_location = Repository(GITHUB_OWNER, arguments.github_policy)

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

    results = ".compliance"

    # Load policy engine
    engine = PolicyEngine(
        repository=policy_location,
        path=arguments.github_policy_path,
    )

    Octokit.info("Finished loading policy")

    Octokit.endGroup()

    # run plugin pre-hooks
    engine.plugins.runPre()

    errors = 0

    try:
        errors = engine.check()

    except Exception as err:
        Octokit.error("Unknown Exception was hit, please repo this to " + __url__)
        Octokit.error(str(err))

        if arguments.debug:
            raise err

    Octokit.info("Total unacceptable alerts :: " + str(errors))

    # run plugin post-hook
    engine.plugins.runPost()

    if arguments.action == "break" and errors > 0:
        Octokit.error("Unacceptable Threshold of Risk has been hit!")
        exit(1)
    elif arguments.action == "continue":
        Octokit.info("Skipping threshold break check...")
    elif errors == 0:
        Octokit.info("Acceptable risk and no threshold reached.")
    else:
        Octokit.error("Unknown action type :: " + str(arguments.action))
