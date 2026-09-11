# ZS-PY-003 and ZS-PY-008 negative fixture.
#
# Both rules used to match on the callee alone. ZS-PY-003's name, rationale and
# message are all about shell=True, but nothing in its match checked for it, so
# every subprocess.run call in a repository was reported as command injection.
# ZS-PY-008's own description admitted it fired on constant paths.
import subprocess


def list_directory():
    # No shell, so no shell to inject into: each element reaches execve as its
    # own argument. This is the form ZS-PY-003's own fix_suggestion recommends.
    return subprocess.run(["ls", "-la"], capture_output=True)


def run_fixed_command(timeout):
    # shell=False is the default and is explicit here; a tainted timeout is not
    # a command line.
    return subprocess.run(["git", "status"], timeout=timeout)


def load_config():
    # A constant path cannot be traversed.
    with open("config.json") as f:
        return f.read()
