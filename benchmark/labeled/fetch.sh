#!/bin/sh
# Usage: fetch.sh <target-dir>   Clones DVWA to <target-dir> at the pinned commit.
set -e
[ -n "$1" ] || { echo "usage: fetch.sh <target-dir>" >&2; exit 2; }
SHA=$(sed -n 's/^commit: //p' "$(dirname "$0")/dvwa/SOURCE.txt")
git -c core.longpaths=true clone -q https://github.com/digininja/DVWA "$1"
git -C "$1" checkout -q "$SHA"
echo "DVWA at $SHA in $1"
