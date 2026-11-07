import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from secscan import __version__
from secscan.cli import HOOK_MARK, main

from .fakes import samples

SAMPLES = samples()
LINE, SECRET = SAMPLES["github-token"]
POSIX = pytest.mark.skipif(os.name == "nt", reason="git hooks run through sh")


def run(*args: str) -> int:
    return main(list(args))


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        run("--version")
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_scan_exit_codes_and_output(repo, capsys):
    repo.write("ok.py", "print('hello')\n")
    assert run("scan", str(repo.path)) == 0
    assert "No secrets found" in capsys.readouterr().out
    repo.write("leak.py", LINE + "\n")
    assert run("scan", str(repo.path)) == 1
    out = capsys.readouterr().out
    assert "leak.py:1:10  github-token" in out and SECRET not in out
    assert run("scan", str(repo.path), "--exit-zero") == 0


def test_json_and_sarif_to_a_file(repo, tmp_path, capsys):
    repo.write("leak.py", LINE + "\n")
    out = tmp_path / "report.json"
    assert run("scan", str(repo.path), "--format", "json", "-o", str(out)) == 1
    capsys.readouterr()
    assert json.loads(out.read_text())["findings"][0]["rule"] == "github-token"
    sarif = tmp_path / "r.sarif"
    run("scan", str(repo.path), "--format", "sarif", "-o", str(sarif))
    assert json.loads(sarif.read_text())["version"] == "2.1.0"
    assert SECRET not in out.read_text() + sarif.read_text()
    capsys.readouterr()


def test_baseline_workflow(repo, capsys):
    repo.write("old.py", LINE + "\n")
    base = repo.path / ".secscan-baseline.json"
    assert run("baseline", str(repo.path), "-o", str(base)) == 0
    assert "Wrote 1 fingerprint" in capsys.readouterr().out
    # known finding is suppressed (the default baseline file is discovered)
    assert run("scan", str(repo.path)) == 0
    assert "1 suppressed by baseline" in capsys.readouterr().out
    # a new one is not
    repo.write("new.py", SAMPLES["aws-access-key-id"][0] + "\n")
    assert run("scan", str(repo.path)) == 1
    assert "new.py" in capsys.readouterr().out


def test_explicit_missing_baseline_is_an_error(repo, capsys):
    assert run("scan", str(repo.path), "--baseline", str(repo.path / "nope.json")) == 2
    assert "cannot read baseline" in capsys.readouterr().err


def test_staged_mode_sees_only_the_index(repo, capsys):
    repo.write("clean.py", "x = 1\n")
    repo.commit("base")
    repo.write("leak.py", LINE + "\n")
    assert run("scan", "--staged", str(repo.path)) == 0  # not staged yet
    repo.git("add", "leak.py")
    assert run("scan", "--staged", str(repo.path)) == 1
    assert "leak.py:1:10" in capsys.readouterr().out


def test_history_mode_finds_deleted_secret_and_shows_commit(repo, capsys):
    repo.write("c.py", LINE + "\n")
    repo.commit("leak")
    commit = repo.git("rev-parse", "HEAD")
    repo.write("c.py", "x = 1\n")
    repo.commit("remove")
    assert run("scan", str(repo.path)) == 0  # the working tree is clean
    capsys.readouterr()
    assert run("scan", "--history", str(repo.path)) == 1
    assert f"[{commit[:8]}]" in capsys.readouterr().out


def test_history_baseline(repo, capsys):
    repo.write("c.py", LINE + "\n")
    repo.commit("leak")
    assert run("baseline", "--history", str(repo.path), "-o", str(repo.path / "b.json")) == 0
    assert run("scan", "--history", str(repo.path), "--baseline", str(repo.path / "b.json")) == 0


def test_staged_outside_a_repo_is_a_clean_error(tmp_path, capsys):
    assert run("scan", "--staged", str(tmp_path)) == 2
    assert "not inside a git repository" in capsys.readouterr().err


def test_staged_and_history_are_exclusive(capsys):
    with pytest.raises(SystemExit) as exc:
        run("scan", "--staged", "--history")
    assert exc.value.code == 2


def test_exclude_option(repo):
    repo.write("vendor/x.py", LINE + "\n")
    assert run("scan", str(repo.path)) == 1
    assert run("scan", str(repo.path), "--exclude", "vendor") == 0


def test_rules_command(capsys):
    assert run("rules") == 0
    out = capsys.readouterr().out
    assert "github-token" in out and "private-key" in out


def test_install_hook_writes_and_refuses_to_clobber(repo, capsys):
    assert run("install-hook", str(repo.path)) == 0
    hook = repo.path / ".git" / "hooks" / "pre-commit"
    assert HOOK_MARK in hook.read_text()
    assert run("install-hook", str(repo.path)) == 0  # ours: replaced silently
    hook.write_text("#!/bin/sh\necho mine\n")
    assert run("install-hook", str(repo.path)) == 2
    assert "already exists" in capsys.readouterr().err
    assert "echo mine" in hook.read_text()
    assert run("install-hook", str(repo.path), "--force") == 0
    assert HOOK_MARK in hook.read_text()


@POSIX
def test_installed_hook_blocks_a_commit_with_a_secret(repo):
    assert run("install-hook", str(repo.path)) == 0
    env = {**os.environ, "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]}
    repo.write("ok.py", "x = 1\n")
    repo.git("add", "ok.py")
    subprocess.run(["git", "commit", "-q", "-m", "fine"], cwd=repo.path, env=env, check=True)
    repo.write("leak.py", LINE + "\n")
    repo.git("add", "leak.py")
    blocked = subprocess.run(
        ["git", "commit", "-q", "-m", "oops"],
        cwd=repo.path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert blocked.returncode != 0
    # git relays a hook's output on stderr
    assert "github-token" in blocked.stderr and SECRET not in blocked.stdout + blocked.stderr
    assert repo.git("rev-list", "--count", "HEAD") == "1"


def test_python_dash_m_entry_point(repo):
    repo.write("leak.py", LINE + "\n")
    done = subprocess.run(
        [sys.executable, "-m", "secscan", "scan", str(repo.path)], capture_output=True, text=True
    )
    assert done.returncode == 1
    assert "github-token" in done.stdout and SECRET not in done.stdout


def test_text_report_to_a_file_prints_a_pointer_on_stderr(repo, tmp_path, capsys):
    repo.write("leak.py", LINE + "\n")
    out = tmp_path / "r.txt"
    assert run("scan", str(repo.path), "-o", str(out)) == 1
    assert "1 finding(s); report written to" in capsys.readouterr().err
    assert "github-token" in out.read_text()
