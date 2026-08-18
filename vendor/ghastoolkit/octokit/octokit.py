"""Octokit"""

import os
import inspect
import logging
import time
from string import Template
from typing import Any, Callable, Optional, Union
from dataclasses import field, is_dataclass

from requests import Session
from requests.adapters import HTTPAdapter, Retry
from ratelimit import limits, sleep_and_retry

from ghastoolkit.errors import GHASToolkitAuthenticationError, GHASToolkitError
from ghastoolkit.octokit.github import GitHub, Repository
from ghastoolkit.octokit.graphql import QUERIES


# Assume REST requests are being done by a GitHub Token, not
# a GitHub App which has a higher limit
# https://docs.github.com/en/rest/overview/resources-in-the-rest-api?apiVersion=2022-11-28#rate-limiting
REST_MAX_CALLS = 80  # ~5000 per hour
GRAPHQL_MAX_CALLS = 100  # ~5000 per hour

__OCTOKIT_PATH__ = os.path.dirname(os.path.realpath(__file__))

__OCTOKIT_ERRORS__ = {
    400: GHASToolkitError("Bad Request", status=400),
    401: GHASToolkitAuthenticationError(
        "Authentication / Permission Issue", status=401
    ),
    403: GHASToolkitAuthenticationError(
        "Authentication / Permission Issue", status=403
    ),
    404: GHASToolkitError("Not Found", status=404),
    422: GHASToolkitError(
        "Validation failed, or the endpoint has been spammed.", status=422
    ),
    429: GHASToolkitError("Rate limit hit", status=429),
    500: GHASToolkitError("GitHub Server Error", status=500),
}


# Set up logger
logger = logging.getLogger("ghastoolkit.octokit")
LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
if isinstance(logging.getLevelName(LOGLEVEL), int):
    logging.basicConfig(
        level=LOGLEVEL,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


class Octokit:
    """Base class for GitHub API interactions.

    This class provides utility methods for working with GitHub API endpoints
    including path formatting and URL generation for REST and GraphQL APIs.
    """

    @staticmethod
    def route(path: str, repository: Repository, rtype: str = "rest", **options) -> str:
        """Generate full URL for GitHub API endpoint.

        Args:
            path: The API path with optional format placeholders.
            repository: The repository object containing owner and repo information.
            rtype: API type, either "rest" or "graphql".
            **options: Additional format variables to substitute in the path.

        Returns:
            Full URL for the GitHub API endpoint.
        """
        logger.debug(
            f"Generating route for {rtype} API: path={path}, repository={repository.owner}/{repository.repo}"
        )
        formatted_path = Octokit.formatPath(path, repository, **options)

        # Ensure the path starts with a slash for proper URL construction
        if formatted_path and not formatted_path.startswith("/"):
            formatted_path = "/" + formatted_path

        # Select the base URL depending on the API type
        url = GitHub.api_rest if rtype == "rest" else GitHub.api_graphql
        full_url = f"{url}{formatted_path}"
        logger.debug(f"Generated URL: {full_url}")
        return full_url

    @staticmethod
    def formatPath(path: str, repo: Repository, **options) -> str:
        """Format a path by substituting repository information and options.

        Args:
            path: Path template with format placeholders.
            repo: Repository object containing owner and repo name.
            **options: Additional variables to substitute in the path.

        Returns:
            Formatted path with all placeholders replaced.
        """
        logger.debug(
            f"Formatting path: {path} with repo={repo.owner}/{repo.repo} and options={options}"
        )
        formatted_path = path.format(
            owner=repo.owner, org=repo.owner, repo=repo.repo, **options
        )
        logger.debug(f"Formatted path: {formatted_path}")
        return formatted_path


class OctoItem:
    """Base class for GitHub API response items.

    OctoItem provides a flexible way to access data from GitHub API responses.
    It stores all raw response data in the __data__ dictionary and allows accessing
    it either through direct attributes or dictionary-style access.

    This class is meant to be subclassed with dataclass annotations for
    strongly-typed field access.
    """

    __data__: dict = field(default_factory=dict)

    def get(self, name: str, default: Any = None) -> Any:
        """Get attribute or dictionary value with fallback default.

        Args:
            name: The attribute or key to retrieve.
            default: The value to return if the attribute/key is not found.

        Returns:
            The attribute value, dictionary value, or default if not found.
        """
        try:
            # First check if this is a direct attribute
            if name in self.__dict__:
                return self.__dict__[name]
            # Then check in the data dictionary
            elif self.__data__ and name in self.__data__:
                return self.__data__[name]
            else:
                return default
        except Exception:
            # Fall back to default for any exception
            return default

    def __getattr__(self, name: str) -> Any:
        """Get attribute from data dictionary if not found in class.

        This magic method is called when an attribute is not found through
        normal attribute access.

        Args:
            name: The attribute name to retrieve.

        Returns:
            The value from the __data__ dictionary.

        Raises:
            AttributeError: If the attribute is not found in __data__.
        """
        if self.__data__ and name in self.__data__:
            return self.__data__[name]
        raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")


def loadOctoItem(classtype: type, data: dict) -> OctoItem:
    """Load data into an OctoItem subclass.

    Creates a new instance of the given OctoItem subclass and initializes it with
    the data provided. Only the fields defined in the class annotations are passed
    to the constructor, but all data is stored in the __data__ field for access
    via the get() method or attribute access.

    Args:
        classtype: The OctoItem subclass to instantiate.
        data: Dictionary of data to load into the object.

    Returns:
        A new instance of the OctoItem subclass with data loaded.

    Raises:
        Exception: If the classtype is not a subclass of OctoItem or not a dataclass.
    """
    logger.debug(f"Loading data into {classtype.__name__}")

    if not (issubclass(classtype, OctoItem) and is_dataclass(classtype)):
        error_msg = (
            f"Class should be a dataclass OctoItem subclass, got {classtype.__name__}"
        )
        logger.error(error_msg)
        raise Exception(error_msg)

    # Extract only the fields that are defined in the class
    initdata = {}
    available_keys = list(data.keys())
    annotation_keys = list(classtype.__annotations__.keys())

    logger.debug(f"Available data keys: {available_keys}")
    logger.debug(f"Class annotation keys: {annotation_keys}")

    for key, value in data.items():
        if key in classtype.__annotations__:
            initdata[key] = value
            logger.debug(f"Using field '{key}' in constructor")

    # Log fields that are in annotations but not in data
    missing_fields = [k for k in annotation_keys if k not in available_keys]
    if missing_fields:
        logger.debug(f"Missing fields in data: {missing_fields}")

    # Create new instance and store all data
    new = classtype(**initdata)
    new.__data__ = data
    logger.debug(
        f"Created {classtype.__name__} instance with {len(initdata)} constructor fields and {len(data)} total data fields"
    )
    return new


class RestRequest:
    """Class for making REST API requests to GitHub.

    This class handles REST API requests to GitHub endpoints, including:
    - Making authenticated requests with rate limiting
    - Handling pagination of results
    - Error handling and response parsing
    """

    # Max per page that GitHub allows
    PER_PAGE = 100

    # GitHub API version to use
    VERSION = "2022-11-28"

    @staticmethod
    def convert_to_return_type(result: Any, return_type: type) -> Any:
        """Convert API response data to the specified return type.

        Handles conversion of raw dictionary data from API responses to appropriate
        typed objects such as OctoItem instances or collections.

        Args:
            result: The raw API response data (dict or list of dicts)
            return_type: The target type to convert to

        Returns:
            The converted data, or None if no conversion was performed
        """
        logger.debug(f"Converting result to type: {return_type}")

        # Check if it's a Union type
        if hasattr(return_type, "__origin__") and return_type.__origin__ == Union:
            logger.debug(f"Ignoring Union type")
            return None

        # Check if it's a simple OctoItem type
        if inspect.isclass(return_type) and issubclass(return_type, OctoItem):
            if isinstance(result, dict):
                logger.debug(f"Converting dict to {return_type.__name__}")
                return loadOctoItem(return_type, result)
            elif isinstance(result, list) and all(
                isinstance(item, dict) for item in result
            ):
                # Handle case where a single OctoItem is expected but we have a list of dicts
                # This can happen if an API returns a list but the caller expects a single item
                logger.debug(
                    f"Converting list of dicts to a list of {return_type.__name__}"
                )
                return [loadOctoItem(return_type, item) for item in result]
            else:
                logger.warning(
                    f"Cannot convert non-dict result to {return_type.__name__}"
                )
                return None

        # Check if it's a list type with OctoItem elements
        if (
            hasattr(return_type, "__origin__")
            and return_type.__origin__ == list
            and hasattr(return_type, "__args__")
        ):
            subtype = return_type.__args__[0]

            # Check if the subtype is an OctoItem
            if inspect.isclass(subtype) and issubclass(subtype, OctoItem):
                # Handle case where we have a single dict but expect a list
                if isinstance(result, dict):
                    # Verify the dict has the required fields for conversion
                    try:
                        logger.debug(
                            f"Converting single dict to list of {subtype.__name__}"
                        )
                        return [loadOctoItem(subtype, result)]
                    except Exception as e:
                        logger.warning(
                            f"Could not convert dict to {subtype.__name__}: {str(e)}"
                        )
                        return None
                # Normal list conversion
                elif isinstance(result, list):
                    logger.debug(f"Converting list items to {subtype.__name__}")
                    new_results = []
                    for item in result:
                        if isinstance(item, dict):
                            new_results.append(loadOctoItem(subtype, item))
                        else:
                            logger.warning(f"Skipping non-dict item in list conversion")
                    return new_results

        return None

    @staticmethod
    def convert_list_to_octoitems(result: list, item_class: type) -> list:
        """Convert a list of dictionaries to a list of OctoItem instances.

        Args:
            result: List of dictionaries from API response
            item_class: The OctoItem subclass to convert each item to

        Returns:
            List of converted OctoItem instances
        """
        if not isinstance(result, list):
            logger.warning(
                f"Cannot convert non-list result to list of {item_class.__name__}"
            )
            return result

        if not inspect.isclass(item_class) or not issubclass(item_class, OctoItem):
            logger.warning(f"Cannot convert to non-OctoItem class: {item_class}")
            return result

        logger.debug(f"Converting {len(result)} items to {item_class.__name__}")
        return [loadOctoItem(item_class, item) for item in result]

    @staticmethod
    def parse_link_header(link_header: str) -> dict:
        """Parse a Link header from GitHub API response.

        GitHub uses the Link header for pagination as described in:
        https://docs.github.com/en/rest/guides/traversing-with-pagination

        Args:
            link_header: The Link header string from a GitHub API response.

        Returns:
            Dictionary with keys like 'next', 'prev', 'first', 'last' and URL values.
            Returns empty dict if the header is empty or invalid.
        """
        if not link_header:
            return {}

        logger.debug(f"Parsing Link header: {link_header}")
        links = {}

        for link_part in link_header.split(", "):
            if ">" not in link_part or "rel=" not in link_part:
                continue

            # Extract URL and relation parts
            url_part, rel_part = link_part.split(">; ", 1)
            url = url_part.strip("<")
            rel = rel_part.split("=", 1)[1].strip('"')

            links[rel] = url
            logger.debug(f"Found '{rel}' link: {url}")

        return links

    @staticmethod
    def extract_cursor_from_link(next_link: str) -> str:
        """Extract a cursor value from a GitHub API next link URL.

        Args:
            next_link: The URL from the 'next' relation in a Link header.

        Returns:
            Cursor string or None if no cursor found.
        """
        if not next_link:
            return None

        logger.debug(f"Extracting cursor from link: {next_link}")

        # Parse the URL to extract query parameters
        import urllib.parse as urlparse
        from urllib.parse import parse_qs

        # Split the URL into parts and extract the query string
        parsed = urlparse.urlparse(next_link)
        query_params = parse_qs(parsed.query)

        # Check if 'after' is in the query parameters
        if "after" in query_params and query_params["after"]:
            cursor = query_params["after"][0]  # parse_qs returns lists of values

            # Make sure cursor isn't a URL (which would be invalid)
            if not cursor.startswith("http"):
                logger.debug(f"Extracted cursor: {cursor}")
                return cursor
            else:
                logger.debug(
                    "Found 'after' parameter but it contains a URL (invalid cursor)"
                )
                return None
        else:
            logger.debug("No 'after' parameter found in link")
            return None

    def __init__(
        self, repository: Optional[Repository] = None, retries: Optional[Retry] = None
    ) -> None:
        """Initialize a new RestRequest instance.

        Args:
            repository: Optional repository to use. If not provided,
                        the GitHub.repository will be used.
            retries: Optional retry configuration for failed requests.
        """
        self.repository = repository or GitHub.repository
        self.session = Session()

        # Set up headers for GitHub REST API
        # https://docs.github.com/en/rest/overview/resources-in-the-rest-api
        self.session.headers = {
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": RestRequest.VERSION,
            "Authorization": f"Bearer {GitHub.getToken(masked=False)}",
        }

        # Configure retry behavior if provided
        if retries:
            self.session.mount("https://", HTTPAdapter(max_retries=retries))

    @staticmethod
    def restGet(url: str, authenticated: bool = False):
        """Get Request Wrapper."""

        def decorator(func):
            def wrap(self, *args, **kwargs):
                # if the current class has a rest variable, use it
                rest = getattr(self, "rest") if hasattr(self, "rest") else RestRequest()

                params = {}
                args_index = 0
                response = False
                func_info = inspect.getfullargspec(func)
                return_type = func_info.annotations.get("return")
                defaults = func_info.defaults or ()

                # if len(func_info.args) - 1 != len(defaults):
                #     raise Exception("restGet does not support non-default function variables (yet)")

                for argv in func_info.args:
                    if argv == "self":
                        continue
                    elif argv == "response":
                        response = True

                    argv_value = None
                    # if provided
                    if len(args) > args_index:
                        argv_value = args[args_index]
                    elif kwargs.get(argv):
                        argv_value = kwargs.get(argv)

                    elif not argv_value and len(defaults) < 0:
                        argv_value = defaults[len(defaults) - args_index]

                    params[argv] = argv_value
                    args_index += 1

                # print(f"Request parameters :: '{params}'")
                result = rest.get(url, parameters=params, authenticated=authenticated)

                if response:
                    return func(self, response=result, **kwargs)

                # Handle type conversions if a return type is specified
                if return_type:
                    converted_result = RestRequest.convert_to_return_type(
                        result, return_type
                    )
                    if converted_result is not None:
                        return converted_result

                return result

            return wrap

        return decorator

    @sleep_and_retry
    @limits(calls=REST_MAX_CALLS, period=60)
    def get(
        self,
        path: str,
        parameters: dict = {},
        expected: Optional[int] = 200,
        authenticated: bool = False,
        display_errors: bool = True,
        error_handler: Optional[Callable[[int, dict], Any]] = None,
    ) -> Union[dict, list[dict]]:
        """Make a GET request to the GitHub REST API.

        This method handles pagination automatically, combining results from
        multiple pages when applicable.

        Args:
            path: The API path with optional format placeholders.
            parameters: Dictionary of parameters to substitute in the path or add as query params.
            expected: Expected HTTP status code (or None to accept any status code).
            authenticated: Whether the request requires authentication.
            display_errors: Whether to log error messages.
            error_handler: Optional callback function to handle error responses.

        Returns:
            Either a dictionary (for single-item responses) or list of dictionaries (for collection responses).

        Raises:
            GHASToolkitError: For various API errors.
            GHASToolkitAuthenticationError: When authentication is required but not provided.
        """
        logger.debug(
            f"GET request: path={path}, parameters={parameters}, expected={expected}, authenticated={authenticated}"
        )

        repo = self.repository or GitHub.repository
        if not repo:
            error_msg = "Repository needs to be set"
            logger.error(error_msg)
            raise Exception(error_msg)

        url = Octokit.route(path, repo, rtype="rest", **parameters)
        logger.debug(f"Fetching content from URL: {url}")

        # Check authentication
        has_auth = bool(self.session.headers.get("Authorization"))
        logger.debug(f"Authentication header present: {has_auth}")

        if authenticated and not has_auth:
            error_msg = "GitHub Token required for this request"
            logger.error(f"Authentication error: {error_msg}")
            raise GHASToolkitAuthenticationError(error_msg)

        cursor = None
        page = 1  # Page starts at 1

        result = []
        params = {}
        # if the parameter is in the path, ignore it
        for key, param in parameters.items():
            if "{" + key + "}" not in path:
                params[key] = param
                logger.debug(f"Adding query parameter: {key}={param}")

        params["per_page"] = RestRequest.PER_PAGE
        logger.debug(f"Setting per_page parameter to {RestRequest.PER_PAGE}")

        page_count = 0
        total_items = 0

        while True:
            page_count += 1

            if cursor:
                params["after"] = cursor.replace("%3D", "=")
                logger.debug(
                    f"Pagination: Using cursor {params['after']} for page {page_count}"
                )
            else:
                params["page"] = page
                logger.debug(f"Pagination: Fetching page {page} (API page parameter)")

            logger.debug(f"Making request to {url} with parameters: {params}")
            response = self.session.get(url, params=params)
            logger.debug(f"Response status code: {response.status_code}")

            # Log response headers that are relevant for debugging
            important_headers = [
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "X-RateLimit-Reset",
                "X-GitHub-Request-Id",
                "Link",
            ]
            headers_to_log = {
                k: v for k, v in response.headers.items() if k in important_headers
            }
            logger.debug(f"Response headers: {headers_to_log}")

            # Every response should be a JSON (including errors)
            response_json = response.json()

            # Log the response size
            if isinstance(response_json, list):
                logger.debug(f"Received {len(response_json)} items in response")
            elif isinstance(response_json, dict):
                logger.debug(
                    f"Received dictionary response with {len(response_json)} keys"
                )
                if "total_count" in response_json:
                    logger.debug(
                        f"Response indicates total_count: {response_json['total_count']}"
                    )

            # Handle unexpected status codes
            if expected and response.status_code != expected:
                if display_errors:
                    logger.error(
                        f"Error code from server: {response.status_code}, expected: {expected}"
                    )
                    logger.debug(f"Response content: {response.content}")

                # Handle error with callback if provided
                if error_handler:
                    logger.debug("Calling error handler callback")
                    return error_handler(response.status_code, response_json)

                # Handle known errors
                known_error = __OCTOKIT_ERRORS__.get(response.status_code)
                if known_error:
                    logger.error(
                        f"Known error type: {type(known_error).__name__}, status: {known_error.status}"
                    )
                    raise known_error
                else:
                    logger.warning(f"Unknown error status code: {response.status_code}")

            # Handle errors indicated in the response body
            if isinstance(response_json, dict) and response_json.get("message"):
                # Custom error handler callback
                if error_handler:
                    logger.debug(
                        "Calling error handler callback for response with error message"
                    )
                    return error_handler(response.status_code, response_json)

                # Default error handling
                message = response_json.get("message", "No message provided")
                docs = response_json.get(
                    "documentation_url", "No documentation link provided"
                )

                logger.error(f"Error message from server: {message}")
                logger.error(f"Documentation Link: {docs}")

                # Log additional error details if present
                if "errors" in response_json:
                    logger.error(f"Detailed errors: {response_json['errors']}")

                raise GHASToolkitError(f"REST Request failed: {message}", docs=docs)

            if isinstance(response_json, dict):
                logger.debug("Received single object response, returning directly")
                return response_json
            elif not isinstance(response_json, list):
                logger.warning(
                    f"Unexpected response type: {type(response_json).__name__}, expected list or dict"
                )
                return response_json

            # For collection responses, accumulate items
            current_count = len(response_json)
            result.extend(response_json)
            total_items += current_count

            logger.debug(
                f"Added {current_count} items from page {page_count}, total items so far: {total_items}"
            )

            # if the page is not full, we must have hit the end
            if len(response_json) < RestRequest.PER_PAGE:
                logger.debug(
                    f"Received less than {RestRequest.PER_PAGE} items ({current_count}), ending pagination"
                )
                break

            # Use a cursor for pagination if a Link header is present
            if link_header := response.headers.get("Link"):
                logger.debug(f"Processing Link header: {link_header}")

                # Parse the Link header into a dictionary of relations and URLs
                links = self.parse_link_header(link_header)

                # Check if we have a 'next' link for pagination
                if next_link := links.get("next"):
                    logger.debug(f"Found next page link: {next_link}")

                    # Try to extract a cursor from the next link
                    cursor = self.extract_cursor_from_link(next_link)

                    if cursor is None:
                        # No cursor found, just increment the page number
                        logger.debug(
                            "No cursor extracted from next link, will use page-based pagination"
                        )
                        cursor = None

            page += 1

        logger.debug(
            f"Pagination complete: retrieved {len(result)} total items across {page_count} pages"
        )
        return result

    def postJson(
        self, path: str, data: dict, expected: int = 200, parameters={}
    ) -> dict:
        repo = self.repository or GitHub.repository
        if not repo:
            raise GHASToolkitError("Repository needs to be set")

        url = Octokit.route(path, repo, rtype="rest", **parameters)
        logger.debug(f"Posting content to URL :: {url}")

        response = self.session.post(url, json=data)

        if response.status_code != expected:
            logger.error(f"Error code from server :: {response.status_code}")
            logger.error(f"{response.content}")
            known_error = __OCTOKIT_ERRORS__.get(response.status_code)
            if known_error:
                raise known_error
            raise GHASToolkitError("Failed to post data")

        return response.json()

    def patchJson(
        self,
        path: str,
        data: dict,
        expected: Optional[Union[int, list[int]]] = 200,
        parameters={},
    ) -> dict:
        repo = self.repository or GitHub.repository
        if not repo:
            raise GHASToolkitError("Repository needs to be set")

        url = Octokit.route(path, repo, rtype="rest", **parameters)
        logger.debug(f"Patching content from URL :: {url}")

        response = self.session.patch(url, json=data)

        if expected:
            if (isinstance(expected, int) and response.status_code != expected) or (
                isinstance(expected, list) and response.status_code not in expected
            ):
                logger.error(f"Error code from server :: {response.status_code}")
                logger.error(f"{response.content}")
                known_error = __OCTOKIT_ERRORS__.get(response.status_code)
                if known_error:
                    raise known_error
                raise GHASToolkitError("Failed to patch data")

        return response.json()


DEFAULT_GRAPHQL_PATHS = [os.path.join(__OCTOKIT_PATH__, "graphql")]


class GraphQLRequest:
    """Class for making GraphQL requests to GitHub.

    This class handles GraphQL queries to the GitHub GraphQL API, including:
    - Loading queries from files or predefined constants
    - Formatting queries with variables
    - Making authenticated requests with rate limiting
    - Handling pagination with cursors
    """

    def __init__(self, repository: Optional[Repository] = None) -> None:
        """Initialize a new GraphQLRequest instance.

        Args:
            repository: Optional repository to use. If not provided,
                        the GitHub.repository will be used.
        """
        self.repository = repository or GitHub.repository
        self.session = Session()
        self.cursor = ""

        # Set up headers for GraphQL API
        # https://docs.github.com/en/graphql/guides/forming-calls-with-graphql
        self.session.headers = {
            "Accept": "application/vnd.github.hawkgirl-preview+json",
            "Authorization": f"Bearer {GitHub.getToken(masked=False)}",
        }

        # Load default hardcoded queries
        self.queries = QUERIES.copy()

    @sleep_and_retry
    @limits(calls=GRAPHQL_MAX_CALLS, period=60)
    def query(self, name: str, options: dict[str, Any] = {}) -> dict:
        """Run a GraphQL query by name.

        Executes a named query from the queries dictionary with the given options.
        Automatically handles cursors for pagination.

        Args:
            name: Name of the query to execute (must exist in self.queries).
            options: Variables to substitute in the query.

        Returns:
            The parsed JSON response from the GraphQL API.

        Raises:
            GHASToolkitError: If the query doesn't exist or the API call fails.

        References:
            https://docs.github.com/en/graphql/overview/about-the-graphql-api
            https://docs.github.com/en/graphql/overview/rate-limits-and-node-limits-for-the-graphql-api
        """
        logger.debug(f"Loading Query by Name :: {name}")
        query_content = self.queries.get(name)
        logger.debug(f"Looking up query '{name}' in queries dictionary")

        if not query_content:
            logger.error(f"Query '{name}' not found in available queries")
            raise GHASToolkitError(
                f"Failed to load GraphQL query :: {name}",
                docs="https://docs.github.com/en/enterprise-cloud@latest/graphql/overview/about-the-graphql-api",
            )
        else:
            logger.debug(
                f"Found query '{name}', length: {len(query_content)} characters"
            )

        # Handle cursor for pagination
        cursor = f'after: "{self.cursor}"' if self.cursor != "" else ""
        if self.cursor:
            logger.debug(f"Using pagination cursor: {self.cursor}")
        else:
            logger.debug("No pagination cursor set, retrieving first page")

        query = self.formatQuery(query_content, cursor=cursor, **options)
        logger.debug(f"Formatted GraphQL query with {len(options)} variables")

        # Log query parameters but sanitize sensitive information
        safe_options = {
            k: v if k not in ["token", "password"] else "***"
            for k, v in options.items()
        }
        logger.debug(f"Query variables: {safe_options}")

        # Log the endpoint being used
        logger.debug(f"Sending GraphQL request to endpoint: {GitHub.api_graphql}")

        # Execute the request with appropriate timeout
        logger.debug("Executing GraphQL query...")
        start_time = time.time()
        response = self.session.post(
            GitHub.api_graphql, json={"query": query}, timeout=30
        )
        execution_time = time.time() - start_time
        logger.debug(f"GraphQL request completed in {execution_time:.2f} seconds")

        # Log response details
        logger.debug(f"GraphQL response status code: {response.status_code}")
        if response.status_code != 200:
            logger.error(f"GraphQL API Status :: {response.status_code}")
            logger.error(f"GraphQL Content :: {response.content}")
            raise GHASToolkitError(
                f"Failed to get data from GraphQL API",
                docs="https://docs.github.com/en/enterprise-cloud@latest/graphql/overview/about-the-graphql-api",
            )

        rjson = response.json()
        logger.debug("Successfully parsed JSON response")

        # Handle GraphQL-specific errors (which can occur even with HTTP 200)
        if rjson.get("errors"):
            error_count = len(rjson.get("errors"))
            logger.warning(f"GraphQL query returned {error_count} error(s)")

            for i, err in enumerate(rjson.get("errors")):
                message = err.get("message", "Unknown error")
                path = err.get("path", [])
                locations = err.get("locations", [])

                path_str = ".".join(str(p) for p in path) if path else "unknown path"
                loc_str = (
                    ", ".join(
                        f"line {l.get('line', '?')}, col {l.get('column', '?')}"
                        for l in locations
                    )
                    if locations
                    else "unknown location"
                )

                logger.warning(
                    f"GraphQL error {i+1}/{error_count}: {message} at {path_str} ({loc_str})"
                )

                # Log additional error details if present
                if extensions := err.get("extensions"):
                    logger.debug(f"Error extensions: {extensions}")

        # Log data presence
        if "data" in rjson:
            if rjson["data"] is None:
                logger.warning("GraphQL response contains null data")
            else:
                logger.debug("GraphQL response contains data")
                # Log the keys in the data object for debugging
                data_keys = (
                    rjson["data"].keys() if isinstance(rjson["data"], dict) else []
                )
                logger.debug(f"Data contains keys: {list(data_keys)}")
        else:
            logger.warning("GraphQL response does not contain a data field")

        return rjson

    def loadQueries(self, paths: list[str]):
        """Load GraphQL queries from files in the specified paths.

        Args:
            paths: List of directory paths to load GraphQL queries from.
                   Only files with .graphql extension will be loaded.
        """
        logger.debug(f"Loading GraphQL queries from {len(paths)} paths")
        loaded_count = 0

        for path in paths:
            logger.debug(f"Checking path: {path}")
            if not os.path.exists(path):
                logger.warning(f"Query load path does not exist: {path}")
                continue
            if not os.path.isdir(path):
                logger.warning(f"Query path is not a directory: {path}")
                continue

            try:
                files = os.listdir(path)
                logger.debug(f"Found {len(files)} files in {path}")
                graphql_files = [f for f in files if f.endswith(".graphql")]
                logger.debug(f"Found {len(graphql_files)} .graphql files in {path}")

                for file in files:
                    root = os.path.join(path, file)
                    name, ext = os.path.splitext(file)
                    if ext not in [".graphql"]:
                        continue

                    try:
                        with open(root, "r") as handle:
                            data = handle.read()
                        logger.debug(
                            f"Loaded GraphQL Query: {name} ({len(data)} characters)"
                        )
                        self.queries[name] = data
                        loaded_count += 1
                    except Exception as e:
                        logger.error(f"Error loading query file {root}: {str(e)}")
            except Exception as e:
                logger.error(f"Error processing path {path}: {str(e)}")

        logger.debug(f"Successfully loaded {loaded_count} GraphQL queries")
        logger.debug(f"Total available queries: {len(self.queries)}")

    def formatQuery(self, query: str, **options) -> str:
        """Format a GraphQL query by substituting variables.

        Uses string.Template to substitute variables in the query string.

        Args:
            query: The GraphQL query template.
            **options: Variables to substitute in the query.

        Returns:
            The formatted query with variables substituted.
        """
        logger.debug(f"Formatting GraphQL query (length: {len(query)})")

        # Check for potentially missing variables
        template = Template(query)
        # Extract variables expected by the template (looking for $identifier pattern)
        import re

        expected_vars = set(re.findall(r"\$([a-zA-Z][a-zA-Z0-9_]*)", query))
        provided_vars = set(options.keys())

        # Log missing variables that might cause issues
        missing_vars = expected_vars - provided_vars
        if missing_vars:
            logger.warning(
                f"Potential missing variables in GraphQL query: {', '.join(missing_vars)}"
            )

        # Log extra variables that won't be used
        extra_vars = provided_vars - expected_vars
        if extra_vars:
            logger.debug(
                f"Extra variables provided but not used in query: {', '.join(extra_vars)}"
            )

        formatted_query = template.safe_substitute(**options)
        logger.debug(f"Query formatting complete (length: {len(formatted_query)})")
        return formatted_query
