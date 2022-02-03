"""
Adds fixture to doctests so we can test examples presented in documentation.
"""

import pytest


@pytest.fixture(autouse=True)
def add_dis_to_doctest(doctest_namespace, disassembler):
    """
    Sets the "dis" variable used on example code to be a disassembler instance.
    (Using IDA for our representative example.)
    """
    doctest_namespace["dis"] = disassembler
