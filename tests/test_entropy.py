from secscan.entropy import entropy_floor, entropy_ok, is_placeholder, shannon


def test_shannon_known_values():
    assert shannon("") == 0.0
    assert shannon("aaaa") == 0.0
    assert shannon("abcd") == 2.0
    assert round(shannon("aabb"), 6) == 1.0


def test_floor_is_capped_by_what_a_short_string_can_reach():
    assert entropy_floor("x", 4.0) == 0.0
    assert entropy_floor("a" * 12, 4.0) < 3.0  # 0.8 * log2(12)
    assert entropy_floor("a" * 64, 4.0) == 4.0  # long strings keep the full floor


def test_entropy_ok_zero_floor_accepts_anything():
    assert entropy_ok("aaaa", 0)
    assert not entropy_ok("aaaaaaaaaaaaaaaaaaaaaaaa", 3.5)
    assert entropy_ok("aB3$kL9#mQ2vR7pX", 3.5)


def test_relaxed_placeholder_only_catches_documented_examples_and_runs():
    assert is_placeholder("AKIAIOSFODNN7EXAMPLE", strict=False)
    assert is_placeholder("x" * 30, strict=False)
    assert is_placeholder("ab" * 20, strict=False)
    assert not is_placeholder("your_token_value_9f8e7d6c", strict=False)


def test_strict_placeholder_rejects_words_templates_and_references():
    for value in (
        "your_password_here",
        "changeme-please",
        "${DATABASE_PASSWORD}",
        "{{ vault.secret }}",
        "<insert-token>",
        "%(secret)s-value",
        "settings.SECRET_KEY",
        "os.environ.get",
        "/etc/ssl/private/key",
        "https://example.org/x",
        "get_secret(name)",
        "$HOME_SECRET_VALUE",
        "0123456789ab",
        "quoted-string",
        "invalid_message_id",
        "pwd#module-pwd",
        "Bare.Quoted.String",
        "libsecret-1-0",
        "IPython.core.magics.osm:OSMagics",
        "SeAssignPrimaryTokenPrivilege",
        "getClientSecretValue",
        "fake_google_client_secret",
        "mock-api-credential-9",
    ):
        assert is_placeholder(value, strict=True), value


def test_strict_placeholder_keeps_real_looking_values():
    assert not is_placeholder("Kq9#vLp2Zx7mWd4R", strict=True)


def test_a_long_passphrase_is_not_mistaken_for_a_slug():
    assert not is_placeholder("correct-horse-battery-staple-9", strict=True)
    assert not is_placeholder("correct-horse-battery-staple", strict=True)


def test_structured_text_rules_do_not_swallow_random_secrets():
    for secret in (
        "Kq9Lp2ZxWd4RmN7v",
        "aB3dE5gH7jK9mN1p",
        "ab12-cd34-ef56-gh78",
        "ZXhhbXBsZQ9a8b7c",
    ):
        assert not is_placeholder(secret, strict=True), secret
