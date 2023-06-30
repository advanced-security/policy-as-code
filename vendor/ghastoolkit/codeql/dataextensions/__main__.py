import os
import argparse
from ghastoolkit.codeql.dataextensions.ext import DataExtensions

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

print(f" Language   :: {args.language} (loaded: {len(de.paths)})")
print()
print(f" Sources    :: {len(de.sources)}")
print(f" Sinks      :: {len(de.sinks)}")
print(f" Summaries  :: {len(de.summaries)}")
print(f" Types      :: {len(de.types)}")
print(f" Neutrals   :: {len(de.neutrals)}")
