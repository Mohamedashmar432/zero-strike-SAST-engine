# True negative for ZS-PY-008: Path.open() takes the path from its receiver, and
# the receiver is a constant pathlib join.
from pathlib import Path

HERE = Path(__file__).parent


def leaked_passwords():
    with (HERE / 'leaked_passwords.txt').open() as handle:
        return handle.read().split('\n')
