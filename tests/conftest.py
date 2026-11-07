from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

GIT_ENV = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.org",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.org",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


class Repo:
    def __init__(self, path: Path) -> None:
        self.path = path

    def git(self, *args: str) -> str:
        env = {**os.environ, **GIT_ENV}
        result = subprocess.run(
            ["git", *args], cwd=self.path, env=env, capture_output=True, text=True, check=True
        )
        return result.stdout.strip()

    def write(self, rel: str, text: str) -> Path:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
        return target

    def commit(self, message: str = "change") -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Repo:
    for key, value in GIT_ENV.items():
        monkeypatch.setenv(key, value)
    folder = tmp_path / "repo"
    folder.mkdir()
    r = Repo(folder)
    r.git("init", "-q", "-b", "main")
    return r
