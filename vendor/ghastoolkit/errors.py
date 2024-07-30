# GHASToolkit Errors


from typing import List, Optional


class GHASToolkitError(Exception):
    """Base class for GHASToolkit errors."""

    def __init__(
        self,
        message: Optional[str] = None,
        docs: Optional[str] = None,
        permissions: Optional[List[str]] = [],
        status: Optional[int] = None,
    ) -> None:
        self.message = message
        self.docs = docs
        self.permissions = permissions
        self.status = status

        super().__init__(message)

    def __str__(self) -> str:
        msg = ""

        if hasattr(self, "message"):
            msg = self.message
        else:
            msg = "An error occurred"

        if status := self.status:
            msg += f" (status code: {status})"

        if permissions := self.permissions:
            msg += "\n\nPermissions Required:"
            for perm in permissions:
                msg += f"\n- {perm}"
        if docs := self.docs:
            msg += f"\n\nFor more information, see: {docs}"

        return msg


class GHASToolkitTypeError(GHASToolkitError):
    """Raised when an invalid type is passed."""


class GHASToolkitAuthenticationError(GHASToolkitError):
    """Raised when an authentication error occurs."""
