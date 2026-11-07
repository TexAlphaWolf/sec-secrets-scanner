import sys
from pathlib import Path

import pytest

from secscan.scanner import (
    SKIP_DIRS,
    Finding,
    Ignorer,
    scan_additions,
    scan_file,
    scan_path,
    scan_text,
)

from .fakes import samples

SAMPLES = samples()
TOKEN_LINE, TOKEN = SAMPLES["github-token"]
AWS_LINE, _ = SAMPLES["aws-access-key-id"]


def make(root: Path, rel: str, text: str | bytes) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def test_scan_text_numbers_lines_from_one():
    found = scan_text(f"a\nb\n{TOKEN_LINE}\n", "x.py")
    assert [(f.path, f.line) for f in found] == [("x.py", 3)]


def test_crlf_and_trailing_text_do_not_confuse_columns():
    (finding,) = scan_text(f"{TOKEN_LINE}\r\nnext\r\n", "x.py")
    assert finding.line == 1


def test_fingerprint_survives_line_moves_but_not_other_secrets_or_paths():
    (a,) = scan_text(TOKEN_LINE, "x.py")
    (moved,) = scan_text("\n\n\n" + TOKEN_LINE, "x.py")
    (other_path,) = scan_text(TOKEN_LINE, "y.py")
    (other_secret,) = scan_text(SAMPLES["aws-access-key-id"][0], "x.py")
    assert a.fingerprint == moved.fingerprint
    assert a.fingerprint != other_path.fingerprint
    assert a.fingerprint != other_secret.fingerprint
    assert TOKEN not in a.fingerprint


def test_redaction_has_a_minimum_length_so_short_secrets_do_not_leak_their_size():
    f = Finding("r", "d", "high", "p", 1, 1, secret="ab", reveal=0)
    assert f.redacted == "****"


def test_directory_scan_finds_nested_files(tmp_path):
    make(tmp_path, "src/deep/config.py", TOKEN_LINE)
    make(tmp_path, "README.md", "nothing here")
    found, stats = scan_path(tmp_path)
    assert [f.path for f in found] == ["src/deep/config.py"]
    assert stats.files == 2


def test_skipped_folders_binary_files_and_large_files(tmp_path):
    for folder in ("node_modules", ".venv", "build"):
        assert folder in SKIP_DIRS
        make(tmp_path, f"{folder}/x.py", TOKEN_LINE)
    make(tmp_path, "blob.dat", b"\0\1\2" + TOKEN_LINE.encode())
    make(tmp_path, "logo.png", TOKEN_LINE)
    make(tmp_path, "app.min.js", TOKEN_LINE)
    make(tmp_path, "big.txt", TOKEN_LINE + "\n" + "x" * 5000)
    found, stats = scan_path(tmp_path, max_size=1000)
    assert found == []
    assert stats.skipped >= 3


def test_invalid_utf8_is_scanned_not_rejected(tmp_path):
    make(tmp_path, "latin.txt", b"caf\xe9\n" + TOKEN_LINE.encode() + b"\n")
    found, _ = scan_path(tmp_path)
    assert len(found) == 1


def test_scan_a_single_file(tmp_path):
    path = make(tmp_path, "one.env", TOKEN_LINE)
    found, stats = scan_path(path)
    assert [f.path for f in found] == ["one.env"]
    assert stats.files == 1


def test_scan_file_handles_unreadable_paths(tmp_path):
    found, stats = scan_file(tmp_path / "missing.txt", "missing.txt", 1000)
    assert found == [] and stats.skipped == 1


def test_secscanignore_and_exclude(tmp_path):
    make(tmp_path, "fixtures/data.txt", TOKEN_LINE)
    make(tmp_path, "docs/guide.md", TOKEN_LINE)
    make(tmp_path, "keep.py", TOKEN_LINE)
    make(tmp_path, ".secscanignore", "# test fixtures\nfixtures/\n")
    found, _ = scan_path(tmp_path, excludes=["docs"])
    assert [f.path for f in found] == ["keep.py"]


def test_ignorer_patterns():
    ig = Ignorer(["*.lock", "vendor", "a/b/c.txt", ""])
    assert ig.matches("poetry.lock")
    assert ig.matches("x/y/poetry.lock")
    assert ig.matches("vendor/lib/x.py")
    assert ig.matches("a/b/c.txt")
    assert not ig.matches("a/b/d.txt")
    assert not ig.matches("src/app.py")


def test_git_repo_scan_honours_gitignore(repo):
    repo.write("kept.py", TOKEN_LINE)
    repo.write(".env", TOKEN_LINE)
    repo.write(".gitignore", ".env\n")
    found, _ = scan_path(repo.path)
    assert [f.path for f in found] == ["kept.py"]


def test_scan_additions_counts_files_and_lines_and_applies_exclusions():
    from secscan.gitio import Addition

    adds = [
        Addition("c1", "a.py", 1, TOKEN_LINE),
        Addition("c1", "a.py", 2, "print('hi')"),
        Addition("c1", "skip/b.py", 1, TOKEN_LINE),
        Addition("c1", "logo.png", 1, TOKEN_LINE),
    ]
    found, stats = scan_additions(adds, Ignorer(["skip"]))
    assert [(f.path, f.commit) for f in found] == [("a.py", "c1")]
    assert (stats.files, stats.lines) == (1, 2)


@pytest.mark.parametrize("name", ["config.json", "settings.yaml", "Makefile", ".env.example"])
def test_any_text_file_name_is_scanned(tmp_path, name):
    make(tmp_path, name, TOKEN_LINE)
    found, _ = scan_path(tmp_path)
    assert len(found) == 1


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symbolic_links_are_never_followed(tmp_path):
    """A repo must not be able to make the scanner read (and report on) files outside it."""
    outside = make(tmp_path, "outside/id_key", TOKEN_LINE)
    project = tmp_path / "project"
    project.mkdir()
    (project / "link.txt").symlink_to(outside)
    make(project, "real.txt", "nothing here")
    found, stats = scan_path(project)
    assert found == []
    assert stats.skipped == 1 and stats.files == 1
