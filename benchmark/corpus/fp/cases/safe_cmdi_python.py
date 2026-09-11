# ZS-PY-031 (subprocess.check_output) and ZS-PY-057 (subprocess.Popen)
# negative fixture.
#
# Both rules asked only for "tainted_argument: true", which is satisfied by a
# tainted identifier anywhere in the call's subtree. Every call below has a
# constant, hard-coded command list at argument 0 and puts the request-derived
# value in a position that never reaches a command line -- cwd, env, timeout.
# Unindexed, all three were reported as CWE-78 command injection.
import subprocess

from flask import request


def git_status_in_user_workspace():
    # The command is a fixed list and shell is off, so each element reaches
    # execve untouched. cwd only selects the directory the process starts in;
    # it is never parsed as a command line, so a tainted cwd cannot inject.
    workspace = request.args.get("workspace")
    return subprocess.check_output(["git", "status", "--porcelain"], cwd=workspace)


def convert_with_user_timeout():
    # A tainted timeout is a number of seconds, not a command.
    timeout = request.args.get("timeout")
    return subprocess.check_output(["/usr/bin/convert", "in.png", "out.png"], timeout=timeout)


def render_with_user_locale():
    # env values are passed to the child as environment variables; the command
    # itself stays constant. This is environment data, not a command line.
    locale = request.args.get("locale")
    process = subprocess.Popen(
        ["/usr/bin/wkhtmltopdf", "report.html", "report.pdf"],
        cwd="/srv/reports",
        env={"LANG": locale},
    )
    return process.wait()
