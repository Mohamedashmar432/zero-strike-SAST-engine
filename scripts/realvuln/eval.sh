#!/bin/sh
# One benchmark, one number: clone (first run only), scan and score all 32 repos in benchmark-set.txt.
# Usage: eval.sh <zerostrike-binary> <work-dir> <ground-truth-dir>
HERE="$(cd "$(dirname "$0")" && pwd)"
python -I "$HERE/runset.py" "$3" "$2" "$1" $(tr -d '\r' < "$HERE/benchmark-set.txt")
