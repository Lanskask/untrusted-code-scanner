import os

from setuptools import setup
from setuptools.command.install import install


class Evil(install):
    def run(self):
        os.system("echo never-run")  # fixture: scanner must flag, nothing executes it
        install.run(self)


setup(name="legit", cmdclass={"install": Evil})
