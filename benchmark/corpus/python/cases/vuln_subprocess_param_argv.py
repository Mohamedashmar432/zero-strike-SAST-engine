# ZS-PY-147: subprocess.Popen() argv built from a function parameter (no real source, no shell=True)
import subprocess


def run_git(cmd):
    return subprocess.Popen(cmd, stdout=subprocess.PIPE)
