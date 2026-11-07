"""Command line: scan, baseline, install-hook, rules.

Exit codes: 0 nothing found, 1 secrets found, 2 usage or environment error.
"""

from __future__ import annotations

import argparse
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

from secscan import __version__, baseline, gitio, report
from secscan.rules import RULES
from secscan.scanner import Finding, Ignorer, Stats, scan_additions, scan_path

HOOK_MARK = "# secscan pre-commit hook"
HOOK_BODY = f"""#!/bin/sh
{HOOK_MARK}
exec secscan scan --staged
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan", description="Find API keys, tokens and private keys in git repositories."
    )
    parser.add_argument("--version", action="version", version=f"secscan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a folder, the staged changes or the whole history")
    scan.add_argument("path", nargs="?", default=".", help="folder or file (default: .)")
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="only the lines about to be committed")
    mode.add_argument("--history", action="store_true", help="every line ever added, all branches")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("-o", "--output", help="write the report to a file")
    scan.add_argument(
        "--baseline", help=f"known findings to ignore (default: ./{baseline.DEFAULT_NAME})"
    )
    scan.add_argument("--exclude", action="append", default=[], metavar="PATTERN")
    scan.add_argument("--max-size", type=int, default=1024, metavar="KIB", help="skip larger files")
    scan.add_argument("--exit-zero", action="store_true", help="exit 0 even when secrets are found")

    base = sub.add_parser("baseline", help="record the current findings as accepted")
    base.add_argument("path", nargs="?", default=".")
    base.add_argument("-o", "--output", default=baseline.DEFAULT_NAME)
    base.add_argument("--history", action="store_true", help="include the whole history")
    base.add_argument("--exclude", action="append", default=[], metavar="PATTERN")
    base.add_argument("--max-size", type=int, default=1024, metavar="KIB")

    hook = sub.add_parser("install-hook", help="run secscan on every commit of a repository")
    hook.add_argument("path", nargs="?", default=".")
    hook.add_argument("--force", action="store_true", help="replace an existing pre-commit hook")

    sub.add_parser("rules", help="list the detection rules")
    return parser


def _collect(args: argparse.Namespace, root: Path) -> tuple[list[Finding], Stats]:
    staged = getattr(args, "staged", False)
    if staged or args.history:
        top = gitio.toplevel(root)
        ignorer = Ignorer.load(top, args.exclude)
        source = gitio.staged_additions(top) if staged else gitio.history_additions(top)
        return scan_additions(source, ignorer)
    return scan_path(root, args.exclude, args.max_size * 1024)


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.path, f.line, f.column, f.rule_id))


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    findings, stats = _collect(args, root)
    known_path = Path(args.baseline) if args.baseline else root / baseline.DEFAULT_NAME
    suppressed = 0
    if args.baseline or (root.is_dir() and known_path.is_file()):
        findings, suppressed = baseline.apply(findings, baseline.load(known_path))
    findings = _sorted(findings)
    if args.format == "json":
        text = report.to_json(findings, stats, suppressed)
    elif args.format == "sarif":
        text = report.to_sarif(findings)
    else:
        text = report.to_text(findings, stats, suppressed)
    _emit(text, args.output)
    if findings and args.output and args.format == "text":
        print(f"{len(findings)} finding(s); report written to {args.output}", file=sys.stderr)
    return 1 if findings and not args.exit_zero else 0


def cmd_baseline(args: argparse.Namespace) -> int:
    findings, _ = _collect(args, Path(args.path))
    count = baseline.dump(findings, Path(args.output))
    print(f"Wrote {count} fingerprint(s) to {args.output}")
    return 0


def cmd_install_hook(args: argparse.Namespace) -> int:
    top = gitio.toplevel(Path(args.path))
    hooks = top / ".git" / "hooks"
    if not hooks.is_dir():
        raise gitio.GitError(f"{hooks} does not exist (is this a normal clone?)")
    target = hooks / "pre-commit"
    foreign = target.exists() and HOOK_MARK not in target.read_text(
        encoding="utf-8", errors="replace"
    )
    if foreign and not args.force:
        raise gitio.GitError(f"{target} already exists; use --force to replace it")
    target.write_text(HOOK_BODY, encoding="utf-8", newline="\n")
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"Installed {target}")
    return 0


def cmd_rules(_: argparse.Namespace) -> int:
    width = max(len(r.id) for r in RULES)
    for rule in RULES:
        print(f"{rule.id:<{width}}  {rule.severity:<6}  {rule.description}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "scan": cmd_scan,
        "baseline": cmd_baseline,
        "install-hook": cmd_install_hook,
        "rules": cmd_rules,
    }
    try:
        return handlers[args.command](args)
    except (gitio.GitError, baseline.BaselineError, OSError) as exc:
        print(f"secscan: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
