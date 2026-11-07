"""Time a history scan on a generated repository (synthetic: every commit adds 100 lines).

python tools/bench_history.py [--commits 2000]
"""

from __future__ import annotations

import argparse
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from secscan.gitio import history_additions
from secscan.scanner import Ignorer, scan_additions

WORDS = (
    *("alpha", "beta", "gamma", "delta", "value", "item"),
    *("config", "handler", "request", "response", "user", "data"),
)


def fast_import_stream(commits: int, lines: int) -> bytes:
    rng = random.Random(3)
    out = bytearray()
    for i in range(commits):
        text = "".join(
            f"    {rng.choice(WORDS)}_{j} = {rng.choice(WORDS)}({rng.randint(0, 9999)}, '{rng.choice(WORDS)}')  # {i}\n"
            for j in range(lines)
        ).encode()
        message = f"commit {i}".encode()
        out += b"commit refs/heads/main\n"
        out += f"mark :{i + 1}\ncommitter T <t@x.y> {1_700_000_000 + i * 60} +0000\n".encode()
        out += f"data {len(message)}\n".encode() + message + b"\n"
        if i:
            out += f"from :{i}\n".encode()
        out += f"M 100644 inline src/mod_{i % 50}.py\ndata {len(text)}\n".encode() + text + b"\n"
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commits", type=int, default=2000)
    parser.add_argument("--lines", type=int, default=100, help="lines added by each commit")
    args = parser.parse_args()
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, env=env, check=True)
        subprocess.run(
            ["git", "-c", "user.name=a", "-c", "user.email=a@b.c", "fast-import", "--quiet"],
            cwd=repo,
            env=env,
            input=fast_import_stream(args.commits, args.lines),
            check=True,
        )
        start = time.perf_counter()
        findings, stats = scan_additions(history_additions(repo), Ignorer())
        elapsed = time.perf_counter() - start
    print(
        f"history scan: {args.commits} commits, {stats.lines} added lines, "
        f"{len(findings)} findings, {elapsed:.2f} s, {stats.lines / elapsed:,.0f} lines/s"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
