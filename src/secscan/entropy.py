"""Entropy and placeholder checks: they decide whether a match is worth reporting."""

from __future__ import annotations

import re
from collections import Counter
from math import log2

# Words that show up in documentation, samples and templates, never in a real secret.
_PLACEHOLDER_WORDS = (
    "example",
    "changeme",
    "change_me",
    "change-me",
    "your",
    "placeholder",
    "dummy",
    "fake",
    "mock",
    "sample",
    "redacted",
    "replace",
    "insert",
    "xxxx",
    "todo",
    "fixme",
    "foobar",
    "lorem",
    "<",
    ">",
    "${",
    "{{",
    "%(",
    "$(",
)

# `settings.SECRET_KEY`, `os.environ`, `config.api.token`: a reference, not a value.
_DOTTED_REFERENCE = re.compile(r"^[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)+$")
# Literal values that appear in every tutorial. They are weak, but they are not leaked secrets.
# Identifiers, package names and module paths are structured text, not random secrets:
#   quoted-string  libsecret-1-0  IPython.core.magics.osm:OSMagics  pwd#module-pwd
# A value is a "slug" when short words (or 1-3 digit numbers) are joined by separators. With
# a dot, colon or hash it cannot be a passphrase, so any length is accepted as an identifier;
# with only - or _ it is accepted below _SLUG_MAX, because longer ones may be passphrases.
_SLUG = re.compile(r"^(?:[A-Za-z]{2,}|\d{1,3})(?:[-_.#:](?:[A-Za-z]{2,}|\d{1,3}))+$")
_SLUG_MAX = 24
# SeAssignPrimaryTokenPrivilege, getClientSecretValue: words in CamelCase. Only from 16
# characters up: a random 12-letter string is CamelCase by chance about 1 time in 80.
_CAMEL_MIN = 16
_CAMEL = re.compile(r"^(?:[A-Z][a-z]+){2,}$|^[a-z]+(?:[A-Z][a-z]+)+$")
_COMMON_LITERALS = frozenset(
    {
        *("password", "passwd", "pass", "secret", "token", "apikey", "api_key", "admin"),
        *("root", "user", "username", "test", "testing", "default", "guest", "postgres"),
        *("mysql", "changeit", "letmein", "qwerty"),
    }
)
_SEQUENCES = ("0123456789", "abcdefgh", "qwertyuiop")


def shannon(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    n = len(value)
    return -sum(c / n * log2(c / n) for c in Counter(value).values())


def entropy_floor(value: str, floor: float) -> float:
    """The entropy a string of this length can be expected to reach.

    A 12-character string cannot exceed log2(12) = 3.58 bits per character, so a
    flat threshold of 4.0 would make short secrets invisible. The floor is capped at
    80% of that ceiling.
    """
    if len(value) < 2:
        return 0.0
    return min(floor, 0.8 * log2(len(value)))


def entropy_ok(value: str, floor: float) -> bool:
    return floor <= 0 or shannon(value) >= entropy_floor(value, floor)


def is_placeholder(value: str, *, strict: bool) -> bool:
    """True when the value is clearly not a real secret.

    The relaxed check (strict=False) is for tokens with a distinctive prefix, where a
    match is almost certainly real unless it is a documented example or a run of one
    character. The strict check also rejects words, template syntax and references.
    """
    lower = value.lower()
    if "example" in lower or "xxxx" in lower:
        return True
    if len(set(value)) <= 3:
        return True
    if not strict:
        return False
    if any(word in lower for word in _PLACEHOLDER_WORDS):
        return True
    if lower in _COMMON_LITERALS:
        return True
    if _SLUG.match(value) and (len(value) < _SLUG_MAX or any(c in value for c in ".:#")):
        return True
    if len(value) >= _CAMEL_MIN and _CAMEL.match(value):
        return True
    if value[0] in "$%{" or _DOTTED_REFERENCE.match(value):
        return True
    if "(" in value or ")" in value or value.startswith(("/", "./", "http")):
        return True
    return any(seq in lower or seq[::-1] in lower for seq in _SEQUENCES if len(lower) < 24)
