import os
import inspect
import logging
from string import Template
from typing import Any, Optional, Union
from dataclasses import field, is_dataclass

from requests import Session
from ratelimit import limits, sleep_and_retry

from ghastoolkit.octokit.github import GitHub, Repository


# Assume REST requests are being done by a GitHub Token, not
# a GitHub App which has a higher limit
# https://docs.github.com/en/rest/overview/resources-in-the-rest-api?apiVersion=2022-11-28#rate-limiting
REST_MAX_CALLS = 80  # ~5000 per hour

__OCTOKIT_PATH__ = os.path.dirname(os.path.realpath(__file__))

__OCTOKIT_ERRORS__ = {401: "Authentication Issue"}


# logger
logger = logging.getLogger("ghastoolkit.octokit")


class Octokit:
    @staticmethod
    def route(path: str, repository: Repository, rtype: str = "rest", **options) -> str:
        """Generate Route string"""
        formatted_path = Octokit.formatPath(path, repository, **options)

        if not formatted_path.startswith("/"):
            formatted_path = "/" + formatted_path
        url = GitHub.api_rest if rtype == "rest" else GitHub.api_graphql
        return f"{url}{formatted_path}"

    @staticmethod
    def formatPath(path: str, repo: Repository, **options) -> str:
        formatted_path = path.format(
            owner=repo.owner, org=repo.owner, repo=repo.repo, **options
        )
        return formatted_path


class OctoItem:
    """OctoItem"""

    __data__: dict = field(default_factory=dict)

    def get(self, name: str, default: Any = None) -> Any:
        try:
            return self.__getattr__(name)
        except:
            return default

    def __getattr__(self, name) -> Any:
        """Get Attr"""
        if hasattr(self, name):
            return getattr(self, name)
        elif self.__data__ and self.__data__.get(name):
            return self.__data__.get(name)
        raise Exception(f"Unknown key: {name}")


def loadOctoItem(classtype, data: dict):
    if not issubclass(classtype, OctoItem) and is_dataclass(classtype):
        raise Exception(f"Class should be a OctoItem")

    initdata = {}
    for key, value in data.items():
        if classtype.__annotations__.get(key):
            initdata[key] = value
    new = classtype(**initdata)
    new.__data__ = data
    return new


class RestRequest:
    PER_PAGE = 100
    VERSION: str = "2022-11-28"

    def __init__(self, repository: Optional[Repository] = None) -> None:
        self.repository = repository or GitHub.repository
        self.session = Session()
        # https://docs.github.com/en/rest/overview/authenticating-to-the-rest-api
        self.session.headers = {
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": RestRequest.VERSION,
            "Authorization": f"token {GitHub.token}",
        }

    @staticmethod
    def restGet(url: str, authenticated: bool = False):
        """Get Request Wrapper"""

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

                result = rest.get(url, parameters=params, authenticated=authenticated)

                if response:
                    return func(self, responce=result, **kwargs)

                # TODO: runtime type checking

                # return_type = func_info.annotations.get("return")
                # if return_type and not type(result) is return_type.__origin__:
                #     name = f"{self.__class__.__name__}.{func.__name__}()"
                #     raise Exception(f"Unexpected type returned for `{name}`")

                # return is a list
                if return_type.__origin__ == Union:
                    logger.debug(f"Ignoring Union type")
                elif (
                    return_type
                    and isinstance(result, return_type.__origin__)
                    and return_type.__origin__ == list
                ):
                    subtype = return_type.__args__[0]
                    if issubclass(subtype, OctoItem):
                        new_results = []
                        for rslt in result:
                            new_results.append(loadOctoItem(subtype, rslt))

                        return new_results

                return result

            return wrap

        return decorator

    @sleep_and_retry
    @limits(calls=REST_MAX_CALLS, period=60)
    def get(
        self,
        path: str,
        parameters: dict = {},
        expected: int = 200,
        authenticated: bool = False,
    ) -> Union[dict, list[dict]]:
        """Get Request

        Limits requests based on token
        """
        repo = self.repository or GitHub.repository
        if not repo:
            raise Exception("Repository needs to be set")

        url = Octokit.route(path, repo, rtype="rest", **parameters)
        logger.debug(f"Fetching content from URL :: {url}")

        if authenticated and not self.session.headers.get("Authorization"):
            raise Exception(f"GitHub Token required for this request")

        result = []
        params = {}
        # if the parameter is in the path, ignore it
        for key, param in parameters.items():
            if "{" + key + "}" not in path:
                params[key] = param

        params["per_page"] = RestRequest.PER_PAGE

        page = 1  # index starts at 1

        while True:
            params["page"] = page

            responce = self.session.get(url, params=params)
            responce_json = responce.json()

            if responce.status_code != expected:
                logger.error(f"Error code from server :: {responce.status_code}")
                logger.error(f"Content :: {responce_json}")
                known_error = __OCTOKIT_ERRORS__.get(responce.status_code)
                if known_error:
                    raise Exception(known_error)
                raise Exception("REST Request failed :: non-expected server error")

            if isinstance(responce_json, dict) and responce_json.get("errors"):
                logger.error(responce_json.get("message"))
                raise Exception("REST Request failed :: error from server")

            if isinstance(responce_json, dict):
                return responce_json

            result.extend(responce_json)
            # if the page is not full, we must have hit the end
            if len(responce_json) < RestRequest.PER_PAGE:
                break

            page += 1

        return result

    def postJson(self, path: str, data: dict, expected: int = 200) -> dict:
        repo = self.repository or GitHub.repository
        if not repo:
            raise Exception("Repository needs to be set")

        url = Octokit.route(path, repo, rtype="rest")
        logger.debug(f"Posting content from URL :: {url}")

        response = self.session.post(url, json=data)

        if response.status_code != expected:
            logger.error(f"Error code from server :: {response.status_code}")
            known_error = __OCTOKIT_ERRORS__.get(response.status_code)
            if known_error:
                raise Exception(known_error)
            raise Exception(f"Failed to post data")

        return response.json()


DEFAULT_GRAPHQL_PATHS = [os.path.join(__OCTOKIT_PATH__, "graphql")]


class GraphQLRequest:
    def __init__(self, repository: Optional[Repository] = None) -> None:
        self.repository = repository or GitHub.repository
        self.session = Session()
        self.cursor = ""
        # https://docs.github.com/en/rest/overview/authenticating-to-the-rest-api
        self.session.headers = {
            "Accept": "application/vnd.github.hawkgirl-preview+json",
            "Authorization": f"token {GitHub.token}",
        }
        self.queries = {}

        self.loadQueries(DEFAULT_GRAPHQL_PATHS)

    def query(self, name: str, options: dict[str, Any] = {}) -> dict:
        logger.debug(f"Loading Query by Name :: {name}")
        query_content = self.queries.get(name)

        if not query_content:
            raise Exception(f"Failed to load GraphQL query :: {name}")

        cursor = f'after: "{self.cursor}"' if self.cursor != "" else ""

        query = self.formatQuery(query_content, cursor=cursor, **options)

        response = self.session.post(
            GitHub.api_graphql, json={"query": query}, timeout=30
        )
        if response.status_code != 200:
            logger.error(f"GraphQL API Status :: {response.status_code}")
            logger.error(f"GraphQL Content :: {response.content}")
            raise Exception(f"Failed to get data from GraphQL API")

        rjson = response.json()
        if rjson.get("errors"):
            for err in rjson.get("errors"):
                logger.warning(f"GraphQL Query failed :: {err.get('message')}")

        return rjson

    def loadQueries(self, paths: list[str]):
        for path in paths:
            if not os.path.exists(path):
                logger.debug(f"Query load path does not exist :: {path}")
                continue
            if not os.path.isdir(path):
                logger.debug(f"Query path is not a dir :: {path}")
                continue
            for file in os.listdir(path):
                root = os.path.join(path, file)
                name, ext = os.path.splitext(file)
                if ext not in [".graphql"]:
                    continue

                with open(root, "r") as handle:
                    data = handle.read()
                logger.debug(f"Loaded GraphQL Query :: {name}")
                self.queries[name] = data

    def formatQuery(self, query: str, **options):
        return Template(query).substitute(**options)
