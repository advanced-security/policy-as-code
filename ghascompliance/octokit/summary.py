import os

from ghascompliance.octokit import Octokit


class Summary:
    __SUMMARY_ENV_VAR__ = "GITHUB_STEP_SUMMARY"
    __ICONS__ = {"check": "✅", "cross": "❌", "warning": "⚠️"}
    __HEADER_MAX__ = 4
    __HEADER_MIN__ = 1

    summary = ""

    @staticmethod
    def formatHeader(header: str, level: int) -> str:
        """Returns an HTML formatted header with the given text and level."""
        level = max(min(level, Summary.__HEADER_MAX__), Summary.__HEADER_MIN__)
        return f"<h{level}>{header}</h{level}>\n"

    @staticmethod
    def formatItalics(text: str) -> str:
        """Returns the given text formatted to be in italics."""
        return f"<em>{text}</em>"

    @staticmethod
    def formatTable(headers: list, rows: list[list]) -> str:
        """Returns an HTML formatted tbale with the given headers and rows."""
        if not isinstance(headers, list) or not isinstance(rows, list):
            return

        table = ["<table>"]
        col_count = len(headers)

        # Headers
        table.append(f"<tr><th>{'</th><th>'.join(headers)}</th></tr>")

        # Rows
        for row in rows:
            if not isinstance(row, list):
                continue
            row = row[:col_count] + [""] * (col_count - len(row))
            table.append(f"<tr><td>{'</td><td>'.join(row)}</td></tr>")

        table.append("</table>")
        return f"{''.join(table)}\n"

    @staticmethod
    def addRaw(content: str) -> None:
        """Adds a string to the summary with no additional formatting."""
        Summary.summary += f"{content}\n"

    @staticmethod
    def addLine(content: str) -> None:
        """Adds a string to the summary, ending with a break so new text appears on a new line."""
        Summary.summary += f"{content}<br>\n"

    @staticmethod
    def addHeader(header: str, level: int) -> None:
        """Adds a header with the given level to the next line of the summary."""
        Summary.summary += Summary.formatHeader(header, level)

    @staticmethod
    def addTable(headers: list, rows: list[list]) -> None:
        """Adds an HTML table with the given headers and rows to the summary."""
        Summary.summary += Summary.formatTable(headers, rows)

    @staticmethod
    def addCollapsed(contents: str, summary: str = ""):
        """Adds a collapsed section with an optional summary to display when collapsed."""
        Summary.summary += f"<details><summary>{summary.strip()}</summary>{contents.strip()}</details>\n"

    @staticmethod
    def outputJobSummary() -> None:
        """Outputs the current summary as the job summary."""
        file_path = os.environ.get(Summary.__SUMMARY_ENV_VAR__)

        if not file_path or not os.path.isfile(file_path):
            Octokit.warning(
                f"Unable to find the {Summary.__SUMMARY_ENV_VAR__} environment variable, can't create job summary."
            )
            return
        try:
            with open(file_path, "w") as job_file:
                job_file.write(Summary.summary)
                job_file.close()
        except Exception as ex:
            Octokit.warning(f"Unable to output job summary to file.")
