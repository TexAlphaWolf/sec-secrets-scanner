"""A baseline lists known findings so a team can adopt the scanner on an existing repo.

Only fingerprints are stored (rule, path and a hash of the secret), never the secret.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from secscan.scanner import Finding

DEFAULT_NAME = ".secscan-baseline.json"
VERSION = 1


class BaselineError(ValueError):
    """The baseline file cannot be read or is not a secscan baseline."""


def load(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline {path} is not valid JSON: {exc}") from exc
    if (
        not isinstance(data, dict)
        or data.get("version") != VERSION
        or not isinstance(data.get("fingerprints"), list)
        or not all(isinstance(f, str) for f in data["fingerprints"])
    ):
        raise BaselineError(f"{path} is not a secscan baseline (version {VERSION})")
    return set(data["fingerprints"])


def dump(findings: Iterable[Finding], path: Path) -> int:
    fingerprints = sorted({f.fingerprint for f in findings})
    payload = {"version": VERSION, "fingerprints": fingerprints}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return len(fingerprints)


def apply(findings: list[Finding], known: set[str]) -> tuple[list[Finding], int]:
    """Split findings into new ones and the count suppressed by the baseline."""
    fresh = [f for f in findings if f.fingerprint not in known]
    return fresh, len(findings) - len(fresh)
