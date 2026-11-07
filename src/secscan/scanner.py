"""Scanning: lines, files and directories. Git-specific input lives in gitio.py."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath

from secscan import gitio
from secscan.entropy import entropy_ok, is_placeholder, shannon
from secscan.rules import RULES, Rule

IGNORE_MARK = "secscan:ignore"
IGNORE_FILE = ".secscanignore"
MAX_LINE = 20_000  # characters scanned per line; minified bundles are not worth more

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".idea",
        ".vscode",
    }
)
SKIP_SUFFIXES = (
    *(".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".svg", ".pdf"),
    *(".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".whl", ".iso", ".jar"),
    *(".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".wav"),
    *(".ogg", ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc", ".pyo", ".db"),
    *(".sqlite", ".min.js", ".min.css", ".map"),
)


def _skipped_name(rel: str) -> bool:
    return rel.lower().endswith(SKIP_SUFFIXES)


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    description: str
    severity: str
    path: str
    line: int
    column: int
    secret: str = field(repr=False)  # kept in memory only; never printed or serialised
    reveal: int = 0
    commit: str = ""

    @property
    def redacted(self) -> str:
        """The secret with everything but a public prefix replaced by asterisks."""
        shown = self.secret[: self.reveal]
        return shown + "*" * min(max(len(self.secret) - len(shown), 4), 16)

    @property
    def fingerprint(self) -> str:
        """Stable identity for baselines: survives the line moving, not the secret changing.

        BLAKE2b is used only to avoid writing the secret into the baseline file.
        """
        digest = hashlib.blake2b(self.secret.encode(), digest_size=12).hexdigest()
        return f"{self.rule_id}:{self.path}:{digest}"


@dataclass(slots=True)
class Stats:
    files: int = 0
    lines: int = 0
    skipped: int = 0

    def add(self, other: Stats) -> None:
        self.files += other.files
        self.lines += other.lines
        self.skipped += other.skipped


def scan_line(
    text: str, path: str, line_no: int, rules: Iterable[Rule] = RULES, commit: str = ""
) -> list[Finding]:
    """Findings on one line. A secret matched by an earlier rule is not reported again."""
    if len(text) > MAX_LINE:
        text = text[:MAX_LINE]
    lower = text.lower()
    if IGNORE_MARK in lower:
        return []
    found: list[Finding] = []
    taken: list[tuple[int, int]] = []
    for rule in rules:
        if rule.keywords and not any(k in lower for k in rule.keywords):
            continue
        for match in rule.pattern.finditer(text):
            value = match.group(1)
            start, end = match.span(1)
            if any(start < e and s < end for s, e in taken):
                continue
            if rule.min_entropy and not entropy_ok(value, rule.min_entropy):
                continue
            if is_placeholder(value, strict=rule.strict):
                continue
            taken.append((start, end))
            found.append(
                Finding(
                    rule.id,
                    rule.description,
                    rule.severity,
                    path,
                    line_no,
                    start + 1,
                    value,
                    rule.reveal,
                    commit,
                )
            )
    return found


def scan_text(text: str, path: str, rules: Iterable[Rule] = RULES) -> list[Finding]:
    found: list[Finding] = []
    for number, line in enumerate(text.splitlines(), 1):
        found.extend(scan_line(line, path, number, rules))
    return found


class Ignorer:
    """Path exclusions from `--exclude` and a `.secscanignore` file (fnmatch patterns)."""

    def __init__(self, patterns: Iterable[str] = ()) -> None:
        self.patterns = [p.strip().rstrip("/") for p in patterns if p.strip()]

    @classmethod
    def load(cls, root: Path, extra: Iterable[str] = ()) -> Ignorer:
        patterns = list(extra)
        try:
            lines = (root / IGNORE_FILE).read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        patterns += [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
        return cls(patterns)

    def matches(self, rel_path: str) -> bool:
        parts = PurePosixPath(rel_path).parts
        for pattern in self.patterns:
            if fnmatch(rel_path, pattern) or fnmatch(rel_path, pattern + "/*"):
                return True
            if any(fnmatch(part, pattern) for part in parts):
                return True
        return False


def scan_file(
    path: Path, rel: str, max_size: int, rules: Iterable[Rule] = RULES
) -> tuple[list[Finding], Stats]:
    stats = Stats()
    if path.is_symlink():  # never follow a link out of the repository
        stats.skipped += 1
        return [], stats
    try:
        if path.stat().st_size > max_size:
            stats.skipped += 1
            return [], stats
        data = path.read_bytes()
    except OSError:
        stats.skipped += 1
        return [], stats
    if b"\0" in data[:8000]:
        stats.skipped += 1
        return [], stats
    text = data.decode("utf-8", errors="replace")
    stats.files = 1
    stats.lines = text.count("\n") + 1
    return scan_text(text, rel, rules), stats


def _walk(root: Path) -> Iterator[str]:
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            yield (Path(folder) / name).relative_to(root).as_posix()


def list_files(root: Path) -> list[str]:
    """Files to scan: tracked and untracked-but-not-ignored in a repo, else a plain walk."""
    listed = gitio.tracked_files(root)
    if listed is not None:
        return [f for f in listed if not (set(PurePosixPath(f).parts[:-1]) & SKIP_DIRS)]
    return list(_walk(root))


def scan_path(
    root: Path,
    excludes: Iterable[str] = (),
    max_size: int = 1024 * 1024,
    rules: Iterable[Rule] = RULES,
) -> tuple[list[Finding], Stats]:
    """Scan a file or a directory tree."""
    rules = tuple(rules)
    total = Stats()
    found: list[Finding] = []
    if root.is_file():
        return scan_file(root, root.name, max_size, rules)
    ignorer = Ignorer.load(root, excludes)
    for rel in list_files(root):
        if ignorer.matches(rel) or _skipped_name(rel):
            total.skipped += 1
            continue
        findings, stats = scan_file(root / rel, rel, max_size, rules)
        found.extend(findings)
        total.add(stats)
    return found, total


def scan_additions(
    additions: Iterable[gitio.Addition], ignorer: Ignorer, rules: Iterable[Rule] = RULES
) -> tuple[list[Finding], Stats]:
    """Scan lines added by a diff (staged changes or history)."""
    rules = tuple(rules)
    stats = Stats()
    found: list[Finding] = []
    seen_files: set[str] = set()
    for add in additions:
        if ignorer.matches(add.path) or _skipped_name(add.path):
            continue
        seen_files.add(add.path)
        stats.lines += 1
        found.extend(scan_line(add.text, add.path, add.line, rules, add.commit))
    stats.files = len(seen_files)
    return found, stats


__all__ = [
    "Finding",
    "Ignorer",
    "Stats",
    "scan_additions",
    "scan_file",
    "scan_line",
    "scan_path",
    "scan_text",
    "shannon",
]
