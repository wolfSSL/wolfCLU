#!/usr/bin/env python3
"""Test runner for wolfCLU Python tests.

Discovers and runs all *-test.py files under the tests/ directory.
Intended for use on Windows where `make check` is not available.
"""

import glob
import importlib.util
import os
import sys
import unittest


def load_tests_from_file(path):
    """Load a unittest module from a file path (supports hyphens in names)."""
    name = os.path.splitext(os.path.basename(path))[0].replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return unittest.TestLoader().loadTestsFromModule(module)


def main():
    # Run from the project root so tests can find ./wolfssl and ./certs
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    os.chdir(project_root)

    # Ensure tests can import the shared wolfclu_test helper
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    suite = unittest.TestSuite()
    pattern = os.path.join(script_dir, "**", "*-test.py")
    for test_file in sorted(glob.glob(pattern, recursive=True)):
        suite.addTests(load_tests_from_file(test_file))

    runner = unittest.TextTestRunner(verbosity=2, durations=5)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
