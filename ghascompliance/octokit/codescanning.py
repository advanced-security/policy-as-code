import os
import requests
from ghascompliance.octokit.octokit import OctoRequests, GitHub, Octokit


class CodeScanning(OctoRequests):
    def __init__(self, github: GitHub):
        super().__init__(github=github)
        # set ref parameter

        self.parameters["ref"] = github.ref
        self.pr_info = {}
        if self.github.inPullRequest():
            self.pr_info = self.getPullRequestInfo()

    @OctoRequests.request(
        "GET", "/repos/{owner}/{repo}/code-scanning/alerts", params={"state": "open"}
    )
    def getOpenAlerts(self, response: dict = {}):
        """Get all Open Code Scanning Alerts

        For a pull request, a filter is applied on the alerts to see if they are
        present in the merge base. If they are not, they are not returned.

        https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning#list-code-scanning-alerts-for-a-repository
        """
        if self.github.inPullRequest():
            # Append only alerts that are not present in the base branch
            results = []
            for alert in response:
                if not self.checkAlertIfPresentInBase(alert.get("number")):
                    results.append(alert)
            return results
        return response

    def checkAlertIfPresentInBase(self, alert_number: int) -> bool:
        """Get list of instances for an alert and check if it is present in the
        base branch.

        This is slow as each alert is checked individually. The API doesn't
        support an other way as of early 2023.

        https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning#list-instances-of-a-code-scanning-alert
        """

        full_url = self.github.get("api.rest") + self.format(
            "/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
            alert_number=alert_number,
        )
        base = self.pr_info.get("base", {}).get("ref")
        response = requests.get(
            full_url,
            headers=self.headers,
            params={"ref": f"refs/heads/{base}"},
        )

        if response.status_code != 200:
            Octokit.warning(f"Failed to get alert info: `{alert_number}`")
            return {}

        # print(f" >> {alert_number} :: {len(response.json())}")
        return len(response.json()) > 0


if __name__ == "__main__":
    # Code Scanning Alerts CLI
    # > export PYTHONPATH=$(pwd):$(pwd)/vendor
    # > python ./ghascompliance/octokit/codescanning.py
    github = GitHub(
        repository=os.environ.get("GITHUB_REPOSITORY"),
        token=os.environ.get("GITHUB_TOKEN"),
        ref=os.environ.get("GITHUB_REF"),
    )
    codescanning = CodeScanning(github=github)
    alerts = codescanning.getOpenAlerts()

    print(f"Count of Alerts: {len(alerts)}")

    for index, alert in enumerate(alerts):
        name = alert.get("rule", {}).get("name")
        tool = alert.get("tool", {}).get("name")
        severity = alert.get("rule", {}).get("severity")

        most_recent_instance = alert.get("most_recent_instance")

        if int(alert.get("number")) == 99:
            # print(alert)
            print(
                f"{index:<4} [{tool:^12}] {name} == {severity} ({alert.get('number')})"
            )
