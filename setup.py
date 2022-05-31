#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
from setuptools import setup, find_packages


setup(
    name="dragodis",
    author="DC3",
    url="https://github.com/Defense-Cyber-Crime-Center/Dragodis",
    keywords=["malware", "ida", "idapro", "ghidra", "disassembler"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
    ],
    packages=find_packages(),
    include_package_data=True,
    license="MIT",
    python_requires=">=3.8",
    install_requires=[
        "bytesparse",
        "capstone",
        "rpyc",
        "pyhidra",
        "pywin32; platform_system == 'Windows'",
        "pefile",
        "pyelftools",
    ],
    extras_require={
        "testing": [
            "pytest",
        ]
    }
)
