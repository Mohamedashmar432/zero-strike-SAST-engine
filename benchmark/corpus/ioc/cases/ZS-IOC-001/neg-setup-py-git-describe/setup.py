import subprocess
from setuptools import setup

version = subprocess.check_output(["git", "describe", "--tags"]).decode().strip()
setup(name="demo", version=version)
