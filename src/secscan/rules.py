"""Detection rules.

Each rule is a regular expression whose group 1 is the secret itself, plus the filters
that keep it quiet on ordinary code:

* `keywords`: a cheap lowercase substring test run before the regex, so most rules are
  skipped on most lines (this is what makes scanning fast).
* `min_entropy`: minimum Shannon entropy in bits per character, relaxed for short values.
* `strict`: also reject placeholders, template syntax and code references.
* `reveal`: how many leading characters may be shown in a report. Only tokens with a
  fixed public prefix reveal anything (`ghp_`, `AKIA`); a password reveals nothing.

Order matters: when two rules match the same characters, the first one wins, so the
specific rules come before the generic ones.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern[str]
    keywords: tuple[str, ...] = ()
    min_entropy: float = 0.0
    strict: bool = False
    reveal: int = 0
    severity: str = "high"


def _rule(
    id_: str,
    description: str,
    regex: str,
    keywords: tuple[str, ...] = (),
    *,
    min_entropy: float = 0.0,
    strict: bool = False,
    reveal: int = 0,
    severity: str = "high",
) -> Rule:
    return Rule(
        id_, description, re.compile(regex), keywords, min_entropy, strict, reveal, severity
    )


_AWS_PREFIXES = ("akia", "asia", "agpa", "aida", "aroa", "anpa", "anva", "aipa")

RULES: tuple[Rule, ...] = (
    _rule(
        "private-key",
        "Private key block (RSA, EC, DSA, OpenSSH, PGP)",
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)",
        ("private key",),
        reveal=11,
    ),
    _rule(
        "aws-access-key-id",
        "AWS access key ID",
        r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z2-7]{16})\b",
        _AWS_PREFIXES,
        reveal=4,
    ),
    _rule(
        "aws-secret-access-key",
        "AWS secret access key",
        r"(?i)aws[\w.\-]{0,20}secret[\w.\-]{0,20}['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        ("aws",),
        min_entropy=3.8,
    ),
    _rule(
        "github-fine-grained-token",
        "GitHub fine-grained personal access token",
        r"\b(github_pat_[A-Za-z0-9_]{22,255})\b",
        ("github_pat_",),
        reveal=11,
    ),
    _rule(
        "github-token",
        "GitHub personal, OAuth, app or refresh token",
        r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b",
        ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
        reveal=4,
    ),
    _rule(
        "gitlab-token",
        "GitLab personal access token",
        r"\b(glpat-[A-Za-z0-9_\-]{20})(?![A-Za-z0-9_\-])",
        ("glpat-",),
        reveal=6,
    ),
    _rule(
        "slack-token",
        "Slack API token",
        r"\b(xox[abposr]-[A-Za-z0-9-]{10,72})(?![A-Za-z0-9-])",
        ("xox",),
        reveal=5,
    ),
    _rule(
        "slack-webhook",
        "Slack incoming webhook URL",
        r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24})",
        ("hooks.slack.com",),
        reveal=27,
    ),
    _rule(
        "discord-webhook",
        "Discord webhook URL",
        r"(https://(?:discord|discordapp)\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,72})",
        ("/api/webhooks/",),
        reveal=33,
    ),
    _rule(
        "stripe-key",
        "Stripe live secret or restricted key",
        r"\b((?:sk|rk)_live_[A-Za-z0-9]{24,99})\b",
        ("_live_",),
        reveal=8,
    ),
    _rule(
        "google-api-key",
        "Google API key",
        r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])",
        ("aiza",),
        reveal=4,
    ),
    _rule(
        "anthropic-key",
        "Anthropic API key",
        r"\b(sk-ant-[a-z0-9]{2,6}-[A-Za-z0-9_\-]{60,})",
        ("sk-ant-",),
        reveal=7,
    ),
    _rule(
        "openai-key",
        "OpenAI API key",
        r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{40,})",
        ("sk-",),
        min_entropy=3.5,
        reveal=3,
    ),
    _rule(
        "sendgrid-key",
        "SendGrid API key",
        r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9_\-])",
        ("sg.",),
        reveal=3,
    ),
    _rule(
        "npm-token",
        "npm access token",
        r"\b(npm_[A-Za-z0-9]{36})\b",
        ("npm_",),
        reveal=4,
    ),
    _rule(
        "pypi-token",
        "PyPI upload token",
        r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})",
        ("pypi-",),
        reveal=5,
    ),
    _rule(
        "telegram-bot-token",
        "Telegram bot token",
        r"\b(\d{8,10}:[A-Za-z0-9_\-]{35})(?![A-Za-z0-9_\-])",
        ("bot", "telegram"),
        min_entropy=3.5,
    ),
    _rule(
        "jwt",
        "JSON Web Token",
        r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})",
        ("eyj",),
        reveal=3,
        severity="medium",
    ),
    _rule(
        "url-credentials",
        "Password embedded in a URL (scheme://user:password@host)",
        r"\b[a-z][a-z0-9+.\-]{1,20}://[^\s:@/'\"<>]{1,64}:([^\s:@/'\"<>]{6,64})@[A-Za-z0-9.\-]+",
        ("://",),
        min_entropy=2.5,
        strict=True,
    ),
    _rule(
        "generic-secret",
        "Quoted value assigned to a name that looks like a secret",
        r"(?i)\b[\w.\-]{0,30}(?:secret|token|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|private[_-]?key)[\w.\-]{0,10}['\"]?\s*(?::=|=>|[:=])\s*['\"]([^'\"\s]{12,100})['\"]",
        ("secret", "token", "passwd", "password", "pwd", "key"),
        min_entropy=3.5,
        strict=True,
        severity="medium",
    ),
)

RULES_BY_ID: dict[str, Rule] = {r.id: r for r in RULES}
