import os
import json
import logging
from typing import Any, Dict, Optional, Union
from datetime import datetime, timedelta

logger = logging.getLogger("ghastoolkit.utils.cache")

# A month in minutes
CACHE_MONTH = 30 * 24 * 60
# A week in minutes
CACHE_WEEK = 7 * 24 * 60
# A day in minutes
CACHE_DAY = 24 * 60


class Cache:
    """Cache class for storing and retrieving data."""

    cache_age: int = CACHE_DAY
    """Default cache age in minutes."""

    def __init__(
        self,
        root: Optional[str] = None,
        store: Optional[str] = None,
        age: Union[int, str] = CACHE_DAY,
    ):
        """Initialize Cache.

        Args:
            root (str, optional): Root directory for cache. Defaults to ~/.ghastoolkit/cache.
            store (str, optional): Subdirectory for cache. Defaults to None.
            age (int, str): Cache expiration age in hours. Defaults to 1440mins (24hrs).
        """
        if root is None:
            root = os.path.join(os.path.expanduser("~"), ".ghastoolkit", "cache")
        self.root = root
        self.store = store
        self.cache: Dict[str, Any] = {}

        if isinstance(age, str):
            if age.upper() == "MONTH":
                Cache.cache_age = CACHE_MONTH
            elif age.upper() == "WEEK":
                Cache.cache_age = CACHE_WEEK
            elif age.upper() == "DAY":
                Cache.cache_age = CACHE_DAY
            else:
                Cache.cache_age = CACHE_DAY
        else:
            Cache.cache_age = age

        logger.debug(f"Cache root: {self.root}")

        if not os.path.exists(self.cache_path):
            os.makedirs(self.cache_path, exist_ok=True)

    @property
    def cache_path(self) -> str:
        if self.store is None:
            return self.root
        return os.path.join(self.root, self.store)

    def get_file_age(self, path: str) -> Optional[float]:
        """Get the age of a file in hours."""
        if not os.path.exists(path):
            return None

        file_mtime = os.path.getmtime(path)
        file_time = datetime.fromtimestamp(file_mtime)
        current_time = datetime.now()

        age_hours = (current_time - file_time).total_seconds() / 3600
        logger.debug(f"Cache file age: {age_hours:.2f} hours for {path}")

        return age_hours

    def is_cache_expired(self, path: str, max_age_hours: float = 24.0) -> bool:
        """Check if cache file is expired (older than max_age_hours)."""
        age = self.get_file_age(path)
        if age is None:
            return True

        return age > max_age_hours

    def read(
        self, key: str, file_type: Optional[str] = None, max_age_hours: float = 24.0
    ) -> Optional[Any]:
        """Read from cache."""
        path = os.path.join(self.cache_path, key)
        if file_type:
            path = f"{path}.{file_type}"

        if os.path.exists(path):
            if self.is_cache_expired(path, max_age_hours):
                logger.debug(f"Cache expired ({max_age_hours} hours): {path}")
                return None

            logger.debug(f"Cache hit: {path}")
            with open(path, "r") as file:
                return file.read()
        return None

    def write(self, key: str, value: Any, file_type: Optional[str] = None):
        """Write to cache."""
        if not isinstance(key, str):
            raise ValueError("Key must be a string")
        # Convert value to string if it's not already
        if isinstance(value, str):
            pass
        elif isinstance(value, dict):
            value = json.dumps(value)
        else:
            raise ValueError(f"Value is a unsupported type: {type(value)}")

        path = os.path.join(self.cache_path, key)
        # the key might be a owner/repo
        parent = os.path.dirname(path)
        if not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

        if ftype := file_type:
            path = f"{path}.{ftype}"

        logger.debug(f"Cache write: {path}")
        with open(path, "w") as file:
            file.write(value)
