#!/usr/bin/env python

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="CVEDB", # Replace with your own username
    version="0.0.1",
    author="w3security",
    author_email="alerts@log4j.codes",
    description="The CVEDB python bot and helpers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CVEDB/tools",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache 2 License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3',
    setup_requires=['pytest-runner', 'requests', 'gitpython'],
    tests_require=['pytest']
)
