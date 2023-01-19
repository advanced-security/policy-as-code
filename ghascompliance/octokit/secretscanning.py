import os
import requests
from ghascompliance.octokit.octokit import OctoRequests, GitHub, Octokit


class SecretScanning(OctoRequests):
    @OctoRequests.request(
        "GET", "/repos/{owner}/{repo}/secret-scanning/alerts", params={"state": "open"}
    )
    def getOpenAlerts(self, response: dict = {}):
        """Get all open secret scanning alerts

        If the current ref is a pull request, then the location will be checked
        against the pull request commits to determine if the alert is in the
        current pull request.

        https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning?apiVersion=2022-11-28#list-secret-scanning-alerts-for-a-repository
        https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning?apiVersion=2022-11-28#list-locations-for-a-secret-scanning-alert
        """
        if self.github.inPullRequest():
            results = []
            pr_commits = self.getPullRequestCommits()

            Octokit.debug(f"PR Commits: {pr_commits}")

            for alert in response:
                location_response = requests.get(
                    alert.get("locations_url"), headers=self.headers
                )
                if location_response.status_code != 200:
                    Octokit.warning(
                        f"Failed to get location information for alert {alert.get('number')}"
                    )
                    continue

                for location in location_response.json():
                    if location.get("details", {}).get("commit_sha") in pr_commits:
                        results.append(alert)

            return results
        else:
            return response

    def getPullRequestCommits(self):
        """Get all commits for the current pull request

        https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls?apiVersion=2022-11-28#list-commits-on-a-pull-request
        """
        pull_number = self.github.getPullRequestNumber()
        full_url = self.github.get("api.rest") + self.format(
            "/repos/{owner}/{repo}/pulls/{pull_number}/commits", pull_number=pull_number
        )
        response = requests.get(full_url, headers=self.headers)

        commits = []
        for commit in response.json():
            commits.append(commit.get("sha"))

        return commits


if __name__ == "__main__":
    # Secret Scanning Alerts CLI
    # > export PYTHONPATH=$(pwd)
    # > python ./ghascompliance/octokit/dependabot.py
    github = GitHub(
        repository=os.environ.get("GITHUB_REPOSITORY"),
        token=os.environ.get("GITHUB_TOKEN"),
        ref=os.environ.get("GITHUB_REF"),
    )

    print(f"Check PR: {github.inPullRequest()}")

    secretscanning = SecretScanning(github=github)
    alerts = secretscanning.getOpenAlerts()

    print(f"Open Secret Scanning Alerts: {len(alerts)}")
    for index, alert in enumerate(alerts):
        alert_id = alert.get("number")
        state = alert.get("state")
        secret_name = alert.get("secret_type_display_name")

        print(f"{index:<4} [{state:^8}] {secret_name}")
