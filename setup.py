import codecs
import re

from setuptools import find_packages
from setuptools import setup


def get_version(filename):
    with codecs.open(filename, 'r', 'utf-8') as fp:
        contents = fp.read()
    return re.search(r"__version__ = ['\"]([^'\"]+)['\"]", contents).group(1)


version = get_version('policytools/version.txt')

with open('README.md') as f:
    readme = f.read()

setup(
    name='policytools',
    version=version,
    license='Apache License, Version 2.0',
    description='IAM policy tools',
    long_description=readme,
    long_description_content_type="text/markdown",
    author='samkeen',
    author_email='sam.sjk@gmail.com',
    url='https://github.com/samkeen/policy-tools',
    packages=find_packages(),
    install_requires=[
        'pyyaml'
    ],
    include_package_data=True,

)

# test src dist build with: python setup.py sdist
