# Detection rules

`secscan rules` prints this list. Each rule is a regular expression whose first group is the secret, plus the filters that keep it quiet on ordinary code (see [`src/secscan/rules.py`](../src/secscan/rules.py)).

| Rule | Severity | Matches | Filters |
|---|---|---|---|
| `private-key` | high | the `-----BEGIN ... PRIVATE KEY-----` line (RSA, EC, DSA, OpenSSH, PGP, encrypted) | none: the header alone is enough |
| `aws-access-key-id` | high | `AKIA`, `ASIA`, `AGPA`, `AIDA`, `AROA`, `ANPA`, `ANVA`, `AIPA` + 16 base32 characters | documented examples (`...EXAMPLE`) |
| `aws-secret-access-key` | high | 40 base64 characters assigned to a name containing `aws` and `secret` | entropy |
| `github-fine-grained-token` | high | `github_pat_` + 22 to 255 characters | placeholders |
| `github-token` | high | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36 or more alphanumerics | placeholders |
| `gitlab-token` | high | `glpat-` + 20 characters | placeholders |
| `slack-token` | high | `xoxa-`, `xoxb-`, `xoxp-`, `xoxo-`, `xoxs-`, `xoxr-` tokens | placeholders |
| `slack-webhook` | high | `https://hooks.slack.com/services/T.../B.../...` | placeholders |
| `discord-webhook` | high | `https://discord.com/api/webhooks/<id>/<token>` | placeholders |
| `stripe-key` | high | `sk_live_` or `rk_live_` + 24 or more alphanumerics | placeholders |
| `google-api-key` | high | `AIza` + 35 characters | placeholders |
| `anthropic-key` | high | `sk-ant-<tag>-` + 60 or more characters | placeholders |
| `openai-key` | high | `sk-`, `sk-proj-`, `sk-svcacct-`, `sk-admin-` + 40 or more characters | entropy, placeholders |
| `sendgrid-key` | high | `SG.<22>.<43>` | placeholders |
| `npm-token` | high | `npm_` + 36 alphanumerics | placeholders |
| `pypi-token` | high | `pypi-AgEIcHlwaS5vcmc...` | placeholders |
| `telegram-bot-token` | high | `<8-10 digits>:<35 characters>` on a line mentioning `bot` or `telegram` | entropy |
| `jwt` | medium | three dot-separated base64url parts, the first two starting `eyJ` | placeholders |
| `url-credentials` | high | `scheme://user:password@host` | entropy, strict placeholders |
| `generic-secret` | medium | a quoted value of 12 to 100 characters assigned to a name containing `secret`, `token`, `password`, `passwd`, `pwd`, `api_key`, `access_key`, `auth_key` or `private_key` | entropy, strict placeholders |

Order matters: when two rules match the same characters the first one wins, so a Stripe key assigned to a variable called `secret` is reported once, as `stripe-key`.

## Filters

**Keywords.** Before running a regular expression, a cheap lowercase substring test decides whether the rule can possibly match the line. It makes scanning 1.4 to 1.9 times faster (measured, because the generic rule's keywords are common words).

**Entropy.** Shannon entropy in bits per character. A 12-character string cannot exceed log2(12) = 3.58 bits per character, so a flat threshold of 3.5 would make short secrets invisible; the threshold is capped at 80% of what the length allows.

**Placeholders.** Rejected for every rule: values containing `example` or `xxxx`, or made of three or fewer distinct characters. Rejected as well for the *strict* rules (`url-credentials`, `generic-secret`): words such as `changeme`, `your`, `dummy`, `fake`, `mock`, `redacted`; template syntax (`${...}`, `{{...}}`, `<...>`, `%(...)s`); references and paths (`settings.SECRET_KEY`, `os.environ.get`, `/etc/ssl/key`, `http...`); calls (`get_secret(name)`); literals found in every tutorial (`password`, `admin`, `root`, `test`); and `0123456789`, `abcdefgh` or `qwertyuiop` runs in values shorter than 24 characters.

**Structure.** Identifiers are not random: `quoted-string`, `libsecret-1-0`, `pwd#module-pwd`, `IPython.core.magics.osm:OSMagics`, `SeAssignPrimaryTokenPrivilege`. Words (or numbers of up to three digits) joined by separators are rejected when shorter than 24 characters, or at any length if they contain a dot, colon or hash (a passphrase never does). CamelCase words are rejected from 16 characters. The [limitations](limitations.md) give the cost of these choices.

## Adding a rule

1. Add a `_rule(...)` entry in `rules.py`, specific rules before generic ones. Group 1 is the secret.
2. Add an entry to `samples()` in `tests/fakes.py` that **builds** the credential at run time (never a literal), and to `Gen.secrets()` in `tools/evaluate.py` if it is a fixed-format token.
3. Add a row to the table above (a test checks that every rule is documented).
4. `python tools/evaluate.py` must still report 0 benign lines flagged and recall of at least 99.5%.
