import subprocess
import sys

import pytest

from secscan import gitio
from secscan.gitio import GitError, history_additions, parse_diff, staged_additions, toplevel

from .fakes import samples

TOKEN_LINE, TOKEN = samples()["github-token"]

DIFF = """\
@@COMMIT@@ abc123
diff --git a/one.py b/one.py
index 111..222 100644
--- a/one.py
+++ b/one.py
@@ -1,0 +2,2 @@
+alpha
+beta
@@ -10 +12 @@ def f():
-old
+gamma
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-x
-y
diff --git a/with space.txt b/with space.txt
--- /dev/null
+++ b/with space.txt\t
@@ -0,0 +1 @@
+delta
@@COMMIT@@ def456
diff --git a/two.py b/two.py
--- a/two.py
+++ b/two.py
@@ -0,0 +1 @@
+epsilon
"""


def test_parse_diff_tracks_commit_path_and_line_numbers():
    got = [(a.commit, a.path, a.line, a.text) for a in parse_diff(DIFF.splitlines())]
    assert got == [
        ("abc123", "one.py", 2, "alpha"),
        ("abc123", "one.py", 3, "beta"),
        ("abc123", "one.py", 12, "gamma"),
        ("abc123", "with space.txt", 1, "delta"),
        ("def456", "two.py", 1, "epsilon"),
    ]


def test_parse_diff_ignores_deleted_files_and_binary_notices():
    text = "diff --git a/x b/x\nBinary files a/x and b/x differ\n"
    assert list(parse_diff(text.splitlines())) == []


def test_a_line_that_looks_like_a_header_inside_content_is_still_content():
    text = "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -0,0 +1,2 @@\n+++ not a header\n+-- also\n"
    got = [a.text for a in parse_diff(text.splitlines())]
    assert got == ["++ not a header", "-- also"]


def test_secret_after_a_header_lookalike_is_still_found():
    lines = [
        "diff --git a/f b/f",
        "--- a/f",
        "+++ b/f",
        "@@ -0,0 +1,3 @@",
        "+++ looks like a header",
        "+--- and another",
        "+" + TOKEN_LINE,
    ]
    assert [a.line for a in parse_diff(lines) if TOKEN in a.text] == [3]


def test_context_lines_and_missing_newline_markers_keep_numbering():
    lines = [
        "diff --git a/f b/f",
        "--- a/f",
        "+++ b/f",
        "@@ -5,3 +5,3 @@",
        " keep",
        "-old",
        "+new",
        "\\ No newline at end of file",
        " keep too",
    ]
    assert [(a.line, a.text) for a in parse_diff(lines)] == [(6, "new")]


def test_a_truncated_hunk_does_not_swallow_the_next_header():
    lines = [
        "diff --git a/f b/f",
        "+++ b/f",
        "@@ -0,0 +1,5 @@",
        "+only one line",
        "diff --git a/g b/g",
        "+++ b/g",
        "@@ -0,0 +1 @@",
        "+second file",
    ]
    assert [(a.path, a.text) for a in parse_diff(lines)] == [
        ("f", "only one line"),
        ("g", "second file"),
    ]


def test_toplevel_and_non_repo(repo, tmp_path_factory):
    assert toplevel(repo.path).samefile(repo.path)
    outside = tmp_path_factory.mktemp("plain")
    with pytest.raises(GitError, match="not inside a git repository"):
        toplevel(outside)


def test_missing_git_is_a_clear_error(repo, monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(GitError, match="git is not installed"):
        toplevel(repo.path)
    assert gitio.tracked_files(repo.path) is None


def test_staged_additions_are_exactly_what_will_be_committed(repo):
    repo.write("a.py", "one\n")
    repo.commit("base")
    repo.write("a.py", "one\n" + TOKEN_LINE + "\n")
    repo.write("b.py", "new file\n")
    repo.git("add", "a.py")  # b.py stays untracked: not staged
    got = [(a.path, a.line, a.text) for a in staged_additions(repo.path)]
    assert got == [("a.py", 2, TOKEN_LINE)]


def test_staged_with_nothing_staged_is_empty(repo):
    repo.write("a.py", "one\n")
    repo.commit("base")
    assert list(staged_additions(repo.path)) == []


def test_history_finds_a_secret_that_was_committed_and_then_deleted(repo):
    repo.write("config.py", TOKEN_LINE + "\n")
    repo.commit("oops")
    first = repo.git("rev-parse", "HEAD")
    repo.write("config.py", "TOKEN = None\n")
    repo.commit("fix")
    hits = [a for a in history_additions(repo.path) if TOKEN in a.text]
    assert [(h.commit, h.path) for h in hits] == [(first, "config.py")]


def test_history_covers_other_branches(repo):
    repo.write("a.txt", "x\n")
    repo.commit("base")
    repo.git("checkout", "-q", "-b", "feature")
    repo.write("leak.txt", TOKEN_LINE + "\n")
    repo.commit("leak on a branch")
    repo.git("checkout", "-q", "main")
    assert any(TOKEN in a.text for a in history_additions(repo.path))


def test_history_of_an_empty_repository_is_empty(repo):
    assert list(history_additions(repo.path)) == []


def test_history_outside_a_repository_fails(tmp_path):
    with pytest.raises(GitError):
        list(history_additions(tmp_path))


@pytest.mark.skipif(sys.platform == "win32", reason="the helper is a shell script")
@pytest.mark.parametrize("mode", ["staged", "history"])
def test_scanning_never_runs_commands_configured_in_the_repository(repo, mode):
    """A repository can name a `textconv` program in its own config. Scanning must not run it."""
    marker = repo.path.parent / "executed.txt"
    helper = repo.path.parent / "textconv.sh"
    helper.write_text(f'#!/bin/sh\necho ran > "{marker}"\ncat "$1"\n', encoding="utf-8")
    helper.chmod(0o755)
    repo.git("config", "diff.sneaky.textconv", str(helper))
    repo.write(".gitattributes", "*.py diff=sneaky\n")
    repo.write("a.py", "x = 1\n")
    repo.git("add", "-A")
    if mode == "history":
        repo.git("commit", "-q", "-m", "one")
        list(history_additions(repo.path))
    else:
        list(staged_additions(repo.path))
    assert not marker.exists()
