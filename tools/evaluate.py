"""Measure the scanner: recall on generated secrets, false positives on ordinary code.

    python tools/evaluate.py                     # generated data only
    python tools/evaluate.py --corpus /usr/lib/python3.13 --corpus some/other/tree

Three measurements, each one a claim made in the README:

1. Recall: for every rule, N random secrets in its documented format are placed in
   several kinds of line (assignment, JSON, YAML, shell export, header, comment).
   A hit counts only if the right rule reports exactly that secret.
2. False positives on benign lines that merely look like secrets: UUIDs, hashes, base64,
   environment lookups, placeholders, prose about tokens.
3. Real code: scan the trees given with --corpus and print file:line for every finding so
   a person can judge them. Nothing but the location is printed.

It also times the scan with and without the keyword prefilter.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import random
import sys
import time
import uuid
from collections import Counter
from dataclasses import replace
from pathlib import Path

from secscan.rules import RULES
from secscan.scanner import scan_line, scan_path

UPPER32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
UPPERDIG = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
URLSAFE = ALNUM + "_-"
BASE64 = ALNUM + "/+"
DIGITS = "0123456789"

CONTEXTS = (
    'value = "{}"',
    '{{"credential": "{}"}}',
    "credential: {}",
    "export CREDENTIAL={}",
    'curl -H "X-Auth: {}" https://api.internal/v1',
    "# old key, rotate me: {}",
)


class Gen:
    def __init__(self, seed: int) -> None:
        self.r = random.Random(seed)

    def rand(self, alphabet: str, n: int) -> str:
        return "".join(self.r.choice(alphabet) for _ in range(n))

    def secrets(self) -> dict[str, str]:
        r = self.rand
        return {
            "private-key": "-----BEGIN "
            + self.r.choice(["RSA ", "EC ", "OPENSSH ", ""])
            + "PRIVATE KEY-----",
            "aws-access-key-id": self.r.choice(["AKIA", "ASIA"]) + r(UPPER32, 16),
            "github-fine-grained-token": "github_pat_" + r(ALNUM + "_", self.r.randint(22, 82)),
            "github-token": self.r.choice(["ghp_", "gho_", "ghs_"]) + r(ALNUM, 36),
            "gitlab-token": "glpat-" + r(URLSAFE, 20),
            "slack-token": f"xoxb-{r(DIGITS, 12)}-{r(DIGITS, 12)}-{r(ALNUM, 24)}",
            "slack-webhook": f"https://hooks.slack.com/services/T{r(UPPERDIG, 9)}/B{r(UPPERDIG, 9)}/{r(ALNUM, 24)}",
            "discord-webhook": f"https://discord.com/api/webhooks/{r(DIGITS, 18)}/{r(URLSAFE, 68)}",
            "stripe-key": self.r.choice(["sk_live_", "rk_live_"]) + r(ALNUM, 24),
            "google-api-key": "AIza" + r(URLSAFE, 35),
            "anthropic-key": "sk-ant-api03-" + r(URLSAFE, 90),
            "openai-key": "sk-proj-" + r(URLSAFE, self.r.randint(48, 120)),
            "sendgrid-key": f"SG.{r(URLSAFE, 22)}.{r(URLSAFE, 43)}",
            "npm-token": "npm_" + r(ALNUM, 36),
            "pypi-token": "pypi-AgEIcHlwaS5vcmc" + r(URLSAFE, 70),  # secscan:ignore
            "jwt": f"eyJ{r(URLSAFE, 20)}.eyJ{r(URLSAFE, 30)}.{r(URLSAFE, 40)}",
        }


def synthetic_recall(n: int, seed: int) -> tuple[Counter[str], Counter[str], list[str]]:
    gen = Gen(seed)
    hits: Counter[str] = Counter()
    total: Counter[str] = Counter()
    misses: list[str] = []
    for _ in range(n):
        for rule_id, secret in gen.secrets().items():
            for context in CONTEXTS:
                line = secret if rule_id == "private-key" else context.format(secret)
                total[rule_id] += 1
                found = scan_line(line, "x.txt", 1)
                if len(found) == 1 and found[0].rule_id == rule_id and found[0].secret == secret:
                    hits[rule_id] += 1
                elif len(misses) < 5:
                    misses.append(f"{rule_id}: {[f.rule_id for f in found]}")
    # rules that need a particular shape of line
    names = ("api_key", "password", "secret_token", "auth_token", "DB_PASSWORD", "client_secret")
    # The generic rule depends on entropy and on structure checks, so it gets many more
    # samples, to resolve miss rates well below 1%.
    for length in (12, 16, 24, 32):
        key = f"generic-secret/{length}"
        for _ in range(n * 100):
            secret = gen.rand(ALNUM, length)
            name = gen.r.choice(names)
            line = gen.r.choice(
                [f'{name} = "{secret}"', f"{name}: '{secret}'", f'"{name}": "{secret}"']
            )
            total[key] += 1
            found = scan_line(line, "x.txt", 1)
            if (
                len(found) == 1
                and found[0].rule_id == "generic-secret"
                and found[0].secret == secret
            ):
                hits[key] += 1
    # url-credentials shares the entropy and structure filters, so it gets the same sample size.
    for _ in range(n * 100):
        secret = gen.rand(ALNUM, 16)
        total["url-credentials"] += 1
        found = scan_line(f"DATABASE_URL=postgres://app:{secret}@db.internal:5432/app", "x", 1)
        if len(found) == 1 and found[0].rule_id == "url-credentials" and found[0].secret == secret:
            hits["url-credentials"] += 1
    for _ in range(n):
        secret = gen.rand(BASE64, 40)
        total["aws-secret-access-key"] += 1
        found = scan_line(f'aws_secret_access_key = "{secret}"', "x", 1)
        if found and found[0].rule_id == "aws-secret-access-key" and found[0].secret == secret:
            hits["aws-secret-access-key"] += 1
    for _ in range(n):
        secret = f"{gen.rand(DIGITS, 9)}:{gen.rand(URLSAFE, 35)}"
        total["telegram-bot-token"] += 1
        found = scan_line(f"bot_token = '{secret}'", "x", 1)
        if found and found[0].rule_id == "telegram-bot-token" and found[0].secret == secret:
            hits["telegram-bot-token"] += 1
    return hits, total, misses


def benign_lines(n: int, seed: int) -> dict[str, list[str]]:
    gen = Gen(seed)
    r = gen.r
    kinds: dict[str, list[str]] = {
        "uuid": [],
        "hash in a digest variable": [],
        "base64 blob": [],
        "environment lookup": [],
        "placeholder": [],
        "prose about tokens": [],
        "ordinary assignment": [],
    }
    digests = (hashlib.md5, hashlib.sha1, hashlib.sha256)
    for i in range(n):
        kinds["uuid"].append(f'id = "{uuid.UUID(int=r.getrandbits(128))}"')
        digest = r.choice(digests)(str(i).encode()).hexdigest()
        kinds["hash in a digest variable"].append(
            f'{r.choice(["checksum", "sha", "etag", "commit"])} = "{digest}"'
        )
        blob = base64.b64encode(bytes(r.getrandbits(8) for _ in range(r.randint(30, 90)))).decode()
        kinds["base64 blob"].append(f'data = "{blob}"')
        name = r.choice(["SECRET_KEY", "API_TOKEN", "DB_PASSWORD", "access_key", "auth_token"])
        kinds["environment lookup"].append(
            r.choice(
                [
                    f'{name} = os.environ["{name}"]',
                    f'{name} = os.getenv("{name}", "")',
                    f"{name} = config.get_secret()",
                    f"{name}: ${{{{ secrets.{name} }}}}",
                    f"{name} = getpass.getpass()",
                    f'{name} = "${{{name}}}"',
                ]
            )
        )
        kinds["placeholder"].append(
            r.choice(
                [
                    f'{name} = "your_{name.lower()}_here"',
                    f'{name} = "<{name.lower()}>"',
                    f'{name} = "changeme-{i}"',
                    f'{name} = "xxxxxxxxxxxxxxxxxxxx"',
                    f'{name} = "{"ab" * 12}"',
                    'password = "password"',
                    "postgres://user:password@localhost:5432/db",
                ]
            )
        )
        kinds["prose about tokens"].append(
            r.choice(
                [
                    "The access token expires after one hour; request a new one.",
                    "Rotate the API key every 90 days and never commit it.",
                    "Set the password in the settings page, then log in again.",
                    "See https://example.org/docs/auth for the secret format.",
                ]
            )
        )
        kinds["ordinary assignment"].append(
            f'{r.choice(["name", "title", "path", "mode", "url"])}_{i} = "{gen.rand(ALNUM, r.randint(5, 30))}"'
        )
    return kinds


def fmt_rate(num: int, den: int) -> str:
    return f"{100 * num / den:6.2f}%" if den else "   n/a"


def timed_scan(root: Path) -> tuple[int, int, float]:
    start = time.perf_counter()
    findings, stats = scan_path(root)
    return len(findings), stats.lines, time.perf_counter() - start


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--n", type=int, default=200, help="random secrets per rule and context")
    parser.add_argument("--seed", type=int, default=20261107)
    parser.add_argument("--corpus", action="append", default=[], metavar="DIR")
    args = parser.parse_args()

    hits, total, misses = synthetic_recall(args.n, args.seed)
    print("RECALL on generated secrets (right rule, exactly that secret)")
    print(f"{'rule':<28}{'tested':>8}{'found':>8}{'recall':>9}")
    for rule in sorted(total):
        print(f"{rule:<28}{total[rule]:>8}{hits[rule]:>8}{fmt_rate(hits[rule], total[rule]):>9}")
    print(
        f"{'ALL':<28}{sum(total.values()):>8}{sum(hits.values()):>8}{fmt_rate(sum(hits.values()), sum(total.values())):>9}"
    )
    print(f"overall recall: {100 * sum(hits.values()) / sum(total.values()):.2f}%")
    for miss in misses:
        print(f"  missed example: {miss}")

    print("\nFALSE POSITIVES on benign lines that look like secrets")
    print(f"{'kind':<28}{'lines':>8}{'flagged':>9}{'rate':>9}")
    flagged_total = lines_total = 0
    for kind, lines in benign_lines(args.n * 5, args.seed).items():
        flagged = sum(1 for line in lines if scan_line(line, "x", 1))
        flagged_total += flagged
        lines_total += len(lines)
        print(f"{kind:<28}{len(lines):>8}{flagged:>9}{fmt_rate(flagged, len(lines)):>9}")
    print(f"{'ALL':<28}{lines_total:>8}{flagged_total:>9}{fmt_rate(flagged_total, lines_total):>9}")
    print(f"benign lines flagged: {flagged_total} of {lines_total}")

    for corpus in args.corpus:
        root = Path(corpus)
        if not root.exists():
            print(f"\n{corpus}: not found", file=sys.stderr)
            continue
        findings, stats = scan_path(root)
        by_rule = Counter(f.rule_id for f in findings)
        print(
            f"\nREAL CODE: {corpus}: {stats.files} files, {stats.lines} lines, {len(findings)} findings"
        )
        for rule_id, count in by_rule.most_common():
            print(f"  {rule_id:<26}{count:>5}")
        for f in findings[:200]:
            print(f"  {f.path}:{f.line}  {f.rule_id}")

    probe = Path(args.corpus[0]) if args.corpus and Path(args.corpus[0]).exists() else None
    if probe is not None:
        _, lines, with_filter = timed_scan(probe)
        import secscan.scanner as scanner

        original = scanner.RULES
        scanner.RULES = tuple(replace(r, keywords=()) for r in RULES)
        try:
            start = time.perf_counter()
            scan_path(probe, rules=scanner.RULES)
            without = time.perf_counter() - start
        finally:
            scanner.RULES = original
        print(f"\nSPEED on {probe} ({lines} lines, one thread)")
        print(
            f"  with keyword prefilter    {with_filter:6.2f} s  {lines / with_filter:>9,.0f} lines/s"
        )
        print(f"  without prefilter         {without:6.2f} s  {lines / without:>9,.0f} lines/s")
        print(f"  prefilter speed-up        {without / with_filter:6.1f}x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
