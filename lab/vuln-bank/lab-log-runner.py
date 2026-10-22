#!/usr/bin/env python3
"""Forward Flask output to Docker and an evidence file with a hard size cap."""

import os
import signal
import subprocess
import sys
from pathlib import Path


MAX_LOG_BYTES = 64 * 1024 * 1024
LOG_PATH = Path("/logs/app.log")


def run():
    os.umask(0o077)
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    size = LOG_PATH.stat().st_size if LOG_PATH.exists() else 0
    if size >= MAX_LOG_BYTES:
        print("Vuln-Bank app evidence reached its 64 MiB limit", file=sys.stderr)
        return 1

    child = subprocess.Popen(
        [sys.executable, "-u", "/app/app.py"],
        cwd="/app", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    def stop(signum, _frame):
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    exceeded = False
    with LOG_PATH.open("ab", buffering=0) as log:
        while True:
            data = os.read(child.stdout.fileno(), 4096)
            if not data:
                break
            if size + len(data) > MAX_LOG_BYTES:
                exceeded = True
                stop(signal.SIGTERM, None)
                print("Vuln-Bank app evidence reached its 64 MiB limit", file=sys.stderr)
                break
            log.write(data)
            os.write(sys.stdout.fileno(), data)
            size += len(data)

    if exceeded:
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        return 1
    return child.wait()


if __name__ == "__main__":
    raise SystemExit(run())
