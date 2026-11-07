"""Fake credentials, assembled at run time.

No test file contains a literal that looks like a real token: they are built here from
random characters, so the repository never trips GitHub push protection or secscan
itself, and the shapes are exactly the documented ones.
"""

from __future__ import annotations

import random

_RNG = random.Random(20261107)
UPPER32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
UPPERDIG = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
URLSAFE = ALNUM + "_-"
BASE64 = ALNUM + "/+"
DIGITS = "0123456789"


def rand(alphabet: str, n: int) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


# rule id -> (a line of code containing a secret of that kind, the exact secret)
def samples() -> dict[str, tuple[str, str]]:
    def entry(template: str, secret: str) -> tuple[str, str]:
        return template.format(secret), secret

    slack_hook = f"T{rand(UPPERDIG, 9)}/B{rand(UPPERDIG, 9)}/{rand(ALNUM, 24)}"
    return {
        "private-key": entry("{}", "-----BEGIN RSA PRIVATE KEY-----"),  # secscan:ignore
        "aws-access-key-id": entry('aws_key = "{}"', "AKIA" + rand(UPPER32, 16)),
        "aws-secret-access-key": entry('aws_secret_access_key = "{}"', rand(BASE64, 40)),
        "github-fine-grained-token": entry("export GH={}", "github_pat_" + rand(ALNUM + "_", 82)),
        "github-token": entry('token = "{}"', "ghp_" + rand(ALNUM, 36)),
        "gitlab-token": entry("GITLAB={}", "glpat-" + rand(URLSAFE, 20)),
        "slack-token": entry(
            'SLACK="{}"', f"xoxb-{rand(DIGITS, 12)}-{rand(DIGITS, 12)}-{rand(ALNUM, 24)}"
        ),
        "slack-webhook": entry("url: {}", "https://hooks.slack.com/services/" + slack_hook),
        "discord-webhook": entry(
            "{}", f"https://discord.com/api/webhooks/{rand(DIGITS, 18)}/{rand(URLSAFE, 68)}"
        ),
        "stripe-key": entry('stripe = "{}"', "sk_live_" + rand(ALNUM, 24)),
        "google-api-key": entry('KEY = "{}"', "AIza" + rand(URLSAFE, 35)),
        "anthropic-key": entry("ANTHROPIC={}", "sk-ant-api03-" + rand(URLSAFE, 90)),
        "openai-key": entry("OPENAI={}", "sk-proj-" + rand(URLSAFE, 60)),
        "sendgrid-key": entry("{}", f"SG.{rand(URLSAFE, 22)}.{rand(URLSAFE, 43)}"),
        "npm-token": entry("//registry.npmjs.org/:_authToken={}", "npm_" + rand(ALNUM, 36)),
        "pypi-token": entry("password: {}", "pypi-AgEIcHlwaS5vcmc" + rand(URLSAFE, 70)),
        "telegram-bot-token": entry("bot = '{}'", f"{rand(DIGITS, 9)}:{rand(URLSAFE, 35)}"),
        "jwt": entry(
            "Authorization: Bearer {}",
            f"eyJ{rand(URLSAFE, 20)}.eyJ{rand(URLSAFE, 30)}.{rand(URLSAFE, 40)}",
        ),
        "url-credentials": (
            f"DATABASE_URL=postgres://app:{(pw := rand(ALNUM, 16))}@db.internal:5432/app",
            pw,
        ),
        "generic-secret": entry('api_key = "{}"', rand(ALNUM, 32)),
    }
