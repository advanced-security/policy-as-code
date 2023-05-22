import os
import subprocess
from typing import Optional


def findCodeBinary() -> Optional[list[str]]:
    locations = [["codeql"], ["gh", "codeql"], ["/usr/bin/codeql/codeql"]]

    for location in locations:
        try:
            cmd = location + ["version"]
            with open(os.devnull, "w") as null:
                subprocess.check_call(cmd, stdout=null, stderr=null)

            return location
        except Exception as err:
            print(err)

    return
