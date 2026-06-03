#!/usr/bin/env python3
"""Parallel test runner for wolfCLU Python tests.

Runs each *-test.py file in its own process concurrently. The tests are
I/O-bound (each spawns the wolfssl binary), so file-level parallelism gives
near-linear speedup over the serial run_tests.py.

"""

import glob
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Per-file cap so a single hung test can't run until the CI job-level timeout.
PER_TEST_TIMEOUT = 600


def run_one(test_file, project_root):
    """Run a single test file in its own process."""

    try:
        proc = subprocess.run(
            [sys.executable, test_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=project_root,
            universal_newlines=True,
            timeout=PER_TEST_TIMEOUT,
        )
        return test_file, proc.returncode, proc.stdout
    except subprocess.TimeoutExpired as e:
        out = e.output or ""
        return test_file, 1, out + "\n[TIMEOUT] killed after {}s\n".format(
            PER_TEST_TIMEOUT)


def report(script_dir, test_file, rc):
    """Print a one-line status; return True if the file failed."""
    name = os.path.relpath(test_file, script_dir)
    # 77 is the automake SKIP exit code emitted by test_main().
    status = "PASS" if rc == 0 else ("SKIP" if rc == 77 else "FAIL")
    print("[{}] {}".format(status, name), flush=True)
    return rc not in (0, 77)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    pattern = os.path.join(script_dir, "**", "*-test.py")
    all_files = sorted(glob.glob(pattern, recursive=True))

    default_workers = os.cpu_count() or 4
    workers_env = os.environ.get("WOLFCLU_TEST_JOBS")
    if workers_env:
        try:
            workers = max(1, int(workers_env))
        except ValueError:
            workers = default_workers
    else:
        workers = default_workers

    failed = []  # (name, output)
    skipped = [] # (name)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(run_one, f, project_root) for f in all_files]
        # Report as each file finishes so live status isn't gated on the
        # slowest file (and a hang can't hide already-completed results).
        for fut in as_completed(futures):
            test_file, rc, out = fut.result()
            if report(script_dir, test_file, rc):
                failed.append((os.path.relpath(test_file, script_dir), out))
            if rc == 77:
                skipped.append(os.path.relpath(test_file, script_dir))


    # Dump captured output for any failures so it isn't lost in the noise.
    for name, out in failed:
        print("\n===== FAILED: {} =====".format(name))
        if out:
            print(out, end="" if out.endswith("\n") else "\n")

    total = len(all_files) - len(skipped)
    print(
        "\n{}/{} test files passed. {} skipped.".format(total - len(failed),
                                                        total, len(skipped)),
        flush=True,
    )
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
