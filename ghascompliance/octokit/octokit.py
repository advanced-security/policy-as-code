import os
import json
import yaml
import logging
import requests

from ghastoolkit.octokit.octokit import GitHub

from ghascompliance.__version__ import __name__
from ghascompliance.consts import API_ERRORS


class Octokit:
    __ERRORS__ = []
    __EVENT__ = None
    __PREFIX_WARNING__ = ""

    logger = logging.getLogger(__name__)

    @staticmethod
    def setLevel(level: int = logging.INFO):
        """Set the logging level"""
        Octokit.logger.setLevel(level)

    @staticmethod
    def info(msg):
        """Logging Info"""
        logging.info(msg)
        print(msg)

    @staticmethod
    def debug(msg):
        """Logging Debugging"""
        logging.debug(msg)
        if Octokit.logger.level == logging.DEBUG and Octokit.__EVENT__:
            print("::debug :: {msg}".format(msg=msg))
        elif Octokit.logger.level == logging.DEBUG:
            print("[*] " + msg)

    @staticmethod
    def warning(msg):
        """Logging Warning"""
        prepfix = (
            Octokit.__PREFIX_WARNING__ + " :: " if Octokit.__PREFIX_WARNING__ else ""
        )
        logging.warning(msg)
        if Octokit.__EVENT__:
            print("::warning :: {prefix}{msg}".format(msg=msg, prefix=prepfix))
        else:
            print("[!] " + msg)

    @staticmethod
    def error(msg, file=None, line=0, col=0):
        """Logging Error"""
        Octokit.__ERRORS__.append(msg)
        logging.error(msg)

        if Octokit.__EVENT__:
            print("::error ::{msg}".format(msg=msg), flush=True)
        elif file:
            print(
                "::error file={file},line={line},col={col}::{msg}".format(
                    msg=msg, file=file, line=line, col=col
                ),
                flush=True,
            )
        else:
            print("[!] {msg}".format(msg=msg))

    @staticmethod
    def createGroup(name, warning_prepfix=None):
        """Create Logging Group (for Actions)"""
        Octokit.__PREFIX_WARNING__ = warning_prepfix

        if Octokit.__EVENT__:
            print("::group::{name}".format(name=name))
        else:
            print("{:-^64}".format(" " + name + " "))

    @staticmethod
    def endGroup():
        """End Logging Group (for Actions)"""
        if Octokit.__EVENT__:
            print("::endgroup::")
        Octokit.__PREFIX__ = ""

    @staticmethod
    def setOutput(key, value):
        """Set Actions Output"""
        if Octokit.__EVENT__:
            print("::set-output name={}::{}".format(key, value))
        else:
            Octokit.warning(
                "Setting output is not supported in a non GitHub Action context"
            )
        # subprocess.call(["echo", "::set-output name={}::{}".format(key, value)])

    @staticmethod
    def loadEvents(path: str):
        """Loading Action Event"""
        Octokit.debug("Loading event: " + str(path))
        event = {}

        if path and os.path.exists(path):
            with open(path, "r") as handle:
                event = yaml.safe_load(handle)
            Octokit.__EVENT__ = event
        return event
