"""Reports. Secrets are always redacted: there is deliberately no option to print them."""

from __future__ import annotations

import json
from collections.abc import Sequence

from secscan import __version__
from secscan.rules import RULES
from secscan.scanner import Finding, Stats

REPO_URL = "https://github.com/TexAlphaWolf/sec-secrets-scanner"
_LEVELS = {"high": "error", "medium": "warning"}


def to_text(findings: Sequence[Finding], stats: Stats, suppressed: int = 0) -> str:
    lines = []
    for f in findings:
        where = f"{f.path}:{f.line}:{f.column}"
        commit = f"  [{f.commit[:8]}]" if f.commit else ""
        lines.append(f"{where}  {f.rule_id}  {f.redacted}  ({f.severity}){commit}")
    scanned = f"{stats.files} files, {stats.lines} lines"
    extra = f", {suppressed} suppressed by baseline" if suppressed else ""
    if findings:
        files = len({f.path for f in findings})
        lines.append("")
        lines.append(f"{len(findings)} finding(s) in {files} file(s) ({scanned}{extra})")
    else:
        lines.append(f"No secrets found ({scanned}{extra})")
    return "\n".join(lines)


def _item(f: Finding) -> dict[str, object]:
    item: dict[str, object] = {
        "rule": f.rule_id,
        "severity": f.severity,
        "path": f.path,
        "line": f.line,
        "column": f.column,
        "secret": f.redacted,
        "fingerprint": f.fingerprint,
    }
    if f.commit:
        item["commit"] = f.commit
    return item


def to_json(findings: Sequence[Finding], stats: Stats, suppressed: int = 0) -> str:
    payload = {
        "version": __version__,
        "files": stats.files,
        "lines": stats.lines,
        "suppressed": suppressed,
        "findings": [_item(f) for f in findings],
    }
    return json.dumps(payload, indent=2)


def to_sarif(findings: Sequence[Finding]) -> str:
    """SARIF 2.1.0, the format GitHub code scanning ingests."""
    rules = [
        {
            "id": r.id,
            "name": r.id,
            "shortDescription": {"text": r.description},
            "defaultConfiguration": {"level": _LEVELS.get(r.severity, "warning")},
        }
        for r in RULES
    ]
    results = [
        {
            "ruleId": f.rule_id,
            "level": _LEVELS.get(f.severity, "warning"),
            "message": {"text": f"{f.description}: {f.redacted}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path},
                        "region": {"startLine": f.line, "startColumn": f.column},
                    }
                }
            ],
            "partialFingerprints": {"secscan/v1": f.fingerprint},
        }
        for f in findings
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secscan",
                        "version": __version__,
                        "informationUri": REPO_URL,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
