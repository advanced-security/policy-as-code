from enum import Enum
from typing import List


class SeverityLevelEnum(Enum):
    """Security Level Enum."""

    #  Critical to High issues
    CRITICAL = "critical"
    HIGH = "high"
    ERROR = "error"
    ERRORS = "errors"
    #  Medium to Low issues
    MEDIUM = "medium"
    MODERATE = "moderate"
    LOW = "low"
    WARNING = "warning"
    WARNINGS = "warnings"
    # Informational issues
    NOTE = "note"
    NOTES = "notes"
    # Misc
    ALL = "all"
    NONE = "none"

    @staticmethod
    def load(data: str) -> "SeverityLevelEnum":
        return SeverityLevelEnum[data.upper()]

    @staticmethod
    def getAllSeverities(include_misc: bool = False):
        all_severities = []
        for item in SeverityLevelEnum:
            if not include_misc and item.name in ["ALL", "NONE"]:
                continue
            all_severities.append(item.value)
        return all_severities

    @staticmethod
    def getSeveritiesFromName(severity: str, grouping: str = "higher") -> List[str]:
        """Get the list of severities from a given severity.
        Args:
            severity (str): The severity to get the list of severities from.
            grouping (str): The grouping type to use (higher or lower).
        """
        severities = SeverityLevelEnum.getAllSeverities()
        if severity == "none":
            return []
        elif severity == "all":
            return severities

        if grouping == "higher":
            return severities[: severities.index(severity) + 1]
        elif grouping == "lower":
            return severities[severities.index(severity) :]

        return []
