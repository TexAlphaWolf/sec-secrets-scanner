"""Render docs/demo.png from a real run.

Creates a throw-away git repository with generated fake secrets (one of them committed and
then deleted), runs secscan on it, and draws the real output as a terminal card.

    pip install -e ".[dev]" && playwright install chromium
    python tools/screenshot.py
"""

from __future__ import annotations

import html
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from evaluate import ALNUM, UPPER32, Gen

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "demo.png"
ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Demo",
    "GIT_AUTHOR_EMAIL": "demo@example.org",
    "GIT_COMMITTER_NAME": "Demo",
    "GIT_COMMITTER_EMAIL": "demo@example.org",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, env=ENV, check=True, capture_output=True)


def build_repo(repo: Path) -> None:
    gen = Gen(7)
    git(repo, "init", "-q", "-b", "main")
    (repo / "src").mkdir()
    (repo / "src" / "settings.py").write_text(
        f'DEBUG = False\nAWS_ACCESS_KEY_ID = "AKIA{gen.rand(UPPER32, 16)}"\n', encoding="utf-8"
    )
    (repo / "src" / "app.py").write_text("import settings\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "first version")
    # a token committed by mistake, then removed in the next commit
    (repo / "deploy.sh").write_text(
        f"export GH_TOKEN=ghp_{gen.rand(ALNUM, 36)}\n", encoding="utf-8"
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "add deploy script")
    (repo / "deploy.sh").write_text('export GH_TOKEN="$GH_TOKEN"\n', encoding="utf-8")
    git(repo, "commit", "-q", "-am", "read the token from the environment")
    (repo / "src" / "billing.py").write_text(
        f'STRIPE = "sk_live_{gen.rand(ALNUM, 24)}"\napi_key = "{gen.rand(ALNUM, 32)}"\n',
        encoding="utf-8",
    )


def run(repo: Path, *args: str) -> tuple[str, int]:
    done = subprocess.run(
        [sys.executable, "-m", "secscan", *args],
        cwd=repo,
        env={**ENV, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
    )
    return done.stdout.rstrip(), done.returncode


def colour(line: str) -> str:
    text = html.escape(line)
    text = re.sub(r"\((high)\)", r'(<span class="hi">\1</span>)', text)
    text = re.sub(r"\((medium)\)", r'(<span class="med">\1</span>)', text)
    text = re.sub(r"\[([0-9a-f]{8})\]", r'[<span class="dim">\1</span>]', text)
    text = re.sub(r"^(\S+:\d+:\d+)", r'<span class="loc">\1</span>', text)
    text = re.sub(r"^(\d+ finding\(s\).*)$", r'<span class="sum">\1</span>', text)
    return text


def card(blocks: list[tuple[str, str, int]]) -> str:
    body = []
    for command, output, code in blocks:
        body.append(f'<div class="cmd"><span class="ps">$</span> {html.escape(command)}</div>')
        body.extend(f"<div>{colour(line)}</div>" for line in output.splitlines())
        body.append(f'<div class="dim">exit code {code}</div><div>&nbsp;</div>')
    return f"""<!doctype html><meta charset="utf-8"><style>
body {{ margin: 0; background: #0b1020; padding: 28px; }}
.term {{ width: 1000px; background: #11172b; border: 1px solid #2a3355; border-radius: 10px;
  font: 14px/1.55 ui-monospace, Menlo, Consolas, "DejaVu Sans Mono", monospace; color: #d7def5;
  padding: 18px 22px; box-sizing: border-box; }}
.bar {{ color: #7f8bb3; font-size: 12px; margin-bottom: 12px; }}
.term div {{ white-space: pre; }}
.ps {{ color: #6ee7a8; }} .cmd {{ color: #ffffff; margin-top: 4px; }}
.loc {{ color: #8fb4ff; }} .hi {{ color: #ff7b7b; }} .med {{ color: #ffc66b; }}
.dim {{ color: #7f8bb3; }} .sum {{ color: #ffffff; font-weight: 600; }}
</style><div class="term"><div class="bar">secscan {len(blocks)} commands on a demo repository</div>{"".join(body)}</div>"""


def main() -> int:
    from playwright.sync_api import sync_playwright

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "shop"
        repo.mkdir()
        build_repo(repo)
        blocks = []
        for args in (("scan",), ("scan", "--history")):
            output, code = run(repo, *args)
            blocks.append(("secscan " + " ".join(args), output, code))
        page = card(blocks)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        view = browser.new_page(viewport={"width": 1060, "height": 400}, device_scale_factor=2)
        view.set_content(page)
        view.locator(".term").screenshot(path=str(OUT))
        browser.close()
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
