#!/bin/sh
# Usage: fetch.sh <app> <target-dir>   Clones a third-party labeled app to <target-dir> at the commit pinned in <app>/SOURCE.txt.
# Apps: dvwa xvwa webgoat-net govwa. With a single argument the app is dvwa (the old form: fetch.sh <target-dir>).
set -e
if [ -z "$2" ]; then APP=dvwa; DIR=$1; else APP=$1; DIR=$2; fi
[ -n "$DIR" ] || { echo "usage: fetch.sh <app> <target-dir>" >&2; exit 2; }
SOURCE="$(dirname "$0")/$APP/SOURCE.txt"
[ -f "$SOURCE" ] || { echo "unknown app: $APP" >&2; exit 2; }
URL=$(sed -n 's/^repo: //p' "$SOURCE")
SHA=$(sed -n 's/^commit: //p' "$SOURCE")
git -c core.longpaths=true clone -q "$URL" "$DIR"
git -C "$DIR" checkout -q "$SHA"
echo "$APP at $SHA in $DIR"
