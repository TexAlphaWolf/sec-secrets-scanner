import pytest

from secscan.rules import RULES, RULES_BY_ID
from secscan.scanner import scan_line

from .fakes import ALNUM, rand, samples

SAMPLES = samples()


def test_every_rule_has_a_sample():
    assert set(SAMPLES) == {r.id for r in RULES}


def test_rule_ids_are_unique():
    assert len(RULES_BY_ID) == len(RULES)


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
def test_each_rule_finds_its_secret_exactly_once(rule_id):
    line, secret = SAMPLES[rule_id]
    found = scan_line(line, "f.txt", 1)
    assert [f.rule_id for f in found] == [rule_id]
    assert found[0].secret == secret


@pytest.mark.parametrize("rule_id", sorted(SAMPLES))
def test_redaction_never_reveals_more_than_the_public_prefix(rule_id):
    line, secret = SAMPLES[rule_id]
    (finding,) = scan_line(line, "f.txt", 1)
    shown = finding.redacted
    assert secret not in shown
    assert shown.rstrip("*") == secret[: finding.reveal]
    assert secret[finding.reveal :][:8] not in shown  # nothing past the prefix leaks


def test_secret_is_not_in_repr():
    line, secret = SAMPLES["github-token"]
    (finding,) = scan_line(line, "f.txt", 1)
    assert secret not in repr(finding)


def test_column_points_at_the_secret():
    line, secret = SAMPLES["github-token"]
    (finding,) = scan_line(line, "f.txt", 7)
    assert finding.line == 7
    assert line[finding.column - 1 :].startswith(secret)


@pytest.mark.parametrize(
    "line",
    [
        'aws_key = "AKIAIOSFODNN7EXAMPLE"',
        'token = "ghp_' + "x" * 36 + '"',
        'password = "your_password_here"',
        'password = "${DB_PASSWORD}"',
        'api_key = "{{ vault.api_key }}"',
        'secret = "settings.SECRET_KEY_VALUE"',
        'SECRET_KEY = os.environ["SECRET_KEY"]',
        'password = get_password("prod")',
        'token = "aaaaaaaaaaaaaaaaaaaaaaaa"',
        'password = "short"',
        "checksum = " + '"' + "a3f1" * 16 + '"',
        "commit 9fceb02d0ae598e95dc970b74767f19372d61af8",
        "DATABASE_URL=postgres://user:password@localhost/db",
        "DATABASE_URL=postgres://user:${DB_PASS}@localhost/db",
        "see https://example.org/docs for the token format",
    ],
)
def test_ordinary_code_and_placeholders_are_quiet(line):
    assert scan_line(line, "f.txt", 1) == []


def test_inline_ignore_marker_silences_the_line():
    line, _ = SAMPLES["github-token"]
    assert scan_line(line + "  # secscan:ignore", "f.txt", 1) == []
    assert scan_line(line + "  # SECSCAN:IGNORE", "f.txt", 1) == []


def test_overlapping_matches_are_reported_once_by_the_most_specific_rule():
    # The value is both a Stripe key and the value of a variable called "secret".
    line = f'secret = "sk_live_{rand(ALNUM, 24)}"'
    assert [f.rule_id for f in scan_line(line, "f.txt", 1)] == ["stripe-key"]


def test_two_different_secrets_on_one_line():
    a, _ = SAMPLES["github-token"]
    b, _ = SAMPLES["aws-access-key-id"]
    assert {f.rule_id for f in scan_line(f"{a} {b}", "f.txt", 1)} == {
        "github-token",
        "aws-access-key-id",
    }


def test_very_long_lines_are_truncated_not_skipped():
    line, _ = SAMPLES["github-token"]
    assert len(scan_line(line + " " * 50_000, "f.txt", 1)) == 1
    assert scan_line(" " * 50_000 + line, "f.txt", 1) == []  # beyond the 20,000 characters


@pytest.mark.parametrize("last", ["-", "_", "a", "9"])
def test_tokens_are_found_whatever_character_they_end_with(last):
    # A trailing \b would miss a token ending in "-" (regression: 2% of SendGrid keys).
    secret = "SG." + rand(ALNUM, 22) + "." + rand(ALNUM, 42) + last
    (finding,) = scan_line(f'key = "{secret}"', "f.txt", 1)
    assert finding.rule_id == "sendgrid-key" and finding.secret == secret


@pytest.mark.parametrize(
    "line",
    [
        "token_type = 'quoted-string'",
        "obs_local_part.token_type = 'invalid-obs-local-part'",
        "'pwd': 'pwd#module-pwd',",
        'token_kind = "Invalid_Message_Id"',
    ],
)
def test_identifiers_assigned_to_token_like_names_are_quiet(line):
    assert scan_line(line, "f.txt", 1) == []
