import pytest
import sys

from . import is_running_in_docker

def pytest_configure(config):
    if not is_running_in_docker():
        pytest.exit("ERROR: Tests must run only in Docker!\nUse 'make test' to run all tests or 'make test-specific TEST=path/to/test.py' to run a specific test.")
