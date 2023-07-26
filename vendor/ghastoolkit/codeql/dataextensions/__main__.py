import logging
import os
import argparse
from ghastoolkit.codeql.dataextensions.ext import DataExtensions

logging.basicConfig(format="%(message)s")
parser = argparse.ArgumentParser("ghastoolkit-codeql-dataextensions")
parser.add_argument("-l", "--language", required=True)
parser.add_argument("-i", "--input", required=True)

args = parser.parse_args()

de = DataExtensions(args.language)

if os.path.isfile(args.input):
    de.load(args.input)
elif os.path.isdir(args.input):
    for root, dirs, files in os.walk(args.input):
        for fl in files:
            path = os.path.join(root, fl)
            _, ext = os.path.splitext(fl)
            if ext in [".yml", ".yaml"]:
                de.load(path)

logging.info(f" Language   :: {args.language} (loaded: {len(de.paths)})")
logging.info(f" Sources    :: {len(de.sources)}")
logging.info(f" Sinks      :: {len(de.sinks)}")
logging.info(f" Summaries  :: {len(de.summaries)}")
logging.info(f" Types      :: {len(de.types)}")
logging.info(f" Neutrals   :: {len(de.neutrals)}")
