#!/bin/bash
set -e

export VENDOR="$(pwd)/vendor"
echo "Vendor path: $VENDOR"

echo "[+] Delete all folders in vendor"
rm -rf "$VENDOR/*/"

echo "[+] Install all dependencies"
pipenv run pip freeze > "$VENDOR/requirements.txt"
pip install -r "$VENDOR/requirements.txt" --target=$VENDOR

echo "[+] Clean up vendor folder"
rm -rf $VENDOR/*dist-info && \
    rm -rf $VENDOR/requirements.txt

echo "Completed vendor update"
