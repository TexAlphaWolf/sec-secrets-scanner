"""Everything that talks to git. The rest of the program only sees plain Python values."""

from __future__ import annotations

import re
import subprocess
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
COMMIT_MARK = "@@COMMIT@@ "
# A repository can configure programs that git would run on our behalf (a `textconv` driver
# named in .gitattributes, an fsmonitor hook). Scanning an untrusted repository must never
# execute them, so they are switched off here and with --no-textconv / --no-ext-diff below.
_GIT = ("git", "-c", "core.quotepath=off", "-c", "core.fsmonitor=false")


class GitError(RuntimeError):
    """git is missing, the folder is not a repository, or a git command failed."""


@dataclass(frozen=True, slots=True)
class Addition:
    commit: str
    path: str
    line: int
    text: str


def parse_diff(lines: Iterable[str]) -> Iterator[Addition]:
    """Yield the added lines of a `git diff -U0` / `git log -p -U0` stream.

    A line starting with COMMIT_MARK sets the current commit. The hunk header says how
    many old and new lines follow, and exactly that many lines are content: this is what
    stops an added line such as `++ x` (which the diff shows as `+++ x`) from being
    mistaken for a file header, which would silently drop the lines after it.
    """
    commit = ""
    path = ""
    number = 0
    old_left = new_left = 0
    for raw in lines:
        line = raw.rstrip("\r\n")
        if old_left > 0 or new_left > 0:
            if line.startswith("+"):
                new_left -= 1
                if path:
                    yield Addition(commit, path, number, line[1:])
                number += 1
                continue
            if line.startswith("-"):
                old_left -= 1
                continue
            if line.startswith(" "):
                old_left -= 1
                new_left -= 1
                number += 1
                continue
            if line.startswith("\\"):  # "\ No newline at end of file"
                continue
            old_left = new_left = 0  # malformed or truncated hunk: fall through to headers
        if line.startswith(COMMIT_MARK):
            commit = line[len(COMMIT_MARK) :].strip()
            path = ""
        elif line.startswith("diff --git"):
            path = ""
        elif line.startswith("+++ "):
            target = line[4:].split("\t", 1)[0]
            path = target[2:] if target.startswith("b/") else ""
        elif (hunk := _HUNK.match(line)) is not None:
            old_left = int(hunk.group(1)) if hunk.group(1) is not None else 1
            number = int(hunk.group(2))
            new_left = int(hunk.group(3)) if hunk.group(3) is not None else 1


def _run(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run([*_GIT, *args], cwd=root, capture_output=True, check=False)
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc
    except NotADirectoryError as exc:
        raise GitError(f"not a directory: {root}") from exc


def toplevel(root: Path) -> Path:
    result = _run(root, "rev-parse", "--show-toplevel")
    if result.returncode != 0:
        raise GitError(f"{root} is not inside a git repository")
    return Path(result.stdout.decode("utf-8", errors="replace").strip())


def tracked_files(root: Path) -> list[str] | None:
    """Tracked and untracked-but-not-ignored files, or None outside a repository."""
    try:
        result = _run(root, "ls-files", "-z", "-co", "--exclude-standard")
    except GitError:
        return None
    if result.returncode != 0:
        return None
    names = result.stdout.decode("utf-8", errors="replace").split("\0")
    return sorted(n for n in names if n)


def staged_additions(root: Path) -> Iterator[Addition]:
    """Lines added to the index: exactly what the next commit would publish."""
    result = _run(
        root,
        "diff",
        "--cached",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--diff-filter=ACMR",
    )
    if result.returncode != 0:
        raise GitError(result.stderr.decode("utf-8", errors="replace").strip() or "git diff failed")
    yield from parse_diff(result.stdout.decode("utf-8", errors="replace").splitlines())


def history_additions(root: Path) -> Iterator[Addition]:
    """Every line ever added on any branch or tag, streamed so large repos stay cheap."""
    command = [
        *_GIT,
        "log",
        "--all",
        "-p",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        f"--format={COMMIT_MARK}%H",
    ]
    with tempfile.TemporaryFile() as errors:
        try:
            process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=errors)
        except FileNotFoundError as exc:
            raise GitError("git is not installed or not on PATH") from exc
        assert process.stdout is not None
        finished = False
        try:
            with process.stdout:
                stream = (line.decode("utf-8", errors="replace") for line in process.stdout)
                yield from parse_diff(stream)
            finished = True
        finally:
            # If the consumer stops early (or an error occurs) do not leave git running.
            if not finished:
                process.kill()
            code = process.wait()
        if code != 0:
            errors.seek(0)
            message = errors.read().decode("utf-8", errors="replace").strip()
            if "does not have any commits" in message:
                return
            raise GitError(message or "git log failed")
