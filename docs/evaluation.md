# How it was measured

`python tools/evaluate.py --corpus /usr/lib/python3.13 --corpus <site-packages>` prints everything on this page. CI runs the first two measurements on every push and fails if recall drops below 99.5% or if any benign line is flagged.

## 1. Recall on generated secrets

For each rule, random secrets in its documented format are placed in six kinds of line (assignment, JSON, YAML, shell export, HTTP header, comment). A hit counts only if **the right rule reports exactly that secret**, once.

| Rule | Tested | Found | Recall |
|---|---:|---:|---:|
| every rule except `generic-secret`, 19 rules | 19,800 | 19,800 | 100.00% |
| `generic-secret`, random 12 characters | 20,000 | 19,881 | 99.41% |
| `generic-secret`, random 16 characters | 20,000 | 19,959 | 99.80% |
| `generic-secret`, random 24 characters | 20,000 | 19,999 | 100.00% |
| `generic-secret`, random 32 characters | 20,000 | 19,991 | 99.95% |
| **All** | **99,800** | **99,630** | **99.83%** |

The generic rule gets many more samples because it is the only one that depends on entropy and structure checks, and its misses are a fraction of a percent. A miss there is a random string that, by chance, has a repeated-character pattern (low entropy) or is shaped like CamelCase words.

**Caveat.** The generator follows the documented formats, and the rules were written from the same documentation. This shows that the expressions implement the formats and that the filters do not discard random values; it does **not** show that every real token follows its documentation. No real credentials were used.

## 2. False positives on benign lines

7,000 lines that look like secrets without being one: UUIDs, MD5/SHA-1/SHA-256 digests in variables called `checksum` or `etag`, base64 blobs, environment lookups for names like `SECRET_KEY` and `DB_PASSWORD`, placeholders (`your_..._here`, `<token>`, `changeme-1`, `postgres://user:password@localhost`), prose about tokens and ordinary assignments.

**Result: 0 of 7,000 flagged.** **Caveat:** I wrote these lines after writing the filters, so this is a regression test for the filters, not an independent estimate of the real-world rate. The next measurement is the independent one.

## 3. Real code

Findings on code nobody wrote for this test. Only file and line are printed by the tool; the verdicts below come from reading each line.

| Corpus | Files | Lines | Findings |
|---|---:|---:|---:|
| CPython 3.13 standard library | 602 | 299,587 | 1 |
| 3rd-party packages in a virtualenv (IPython, tornado, playwright, debugpy, ...) | 14,265 | 3,919,197 | 7 |
| The other 79 folders of my portfolio (code I wrote) | 880 | 57,006 | 2 |

Verdicts, one per finding:

| Finding | Verdict |
|---|---|
| `urllib/request.py:56`, a `passwd=` argument | documentation example of how to call an API |
| `winappdbg/sql.py:221` URL with password equal to the user name | documentation example |
| `ThirdPartyNotices.txt:1208`, a `password:` line | example in a README copied into a notices file |
| `tornado/test/auth_test.py` (4 lines) | fake OAuth cookie values in tests |
| `tornado/test/test.key:1` | a real private key, used as a test fixture (the detection is correct) |
| `sec-password-audit/tests/test_cli.py:14` | a made-up password in a test |
| `sec-mini-siem/tests/test_notify.py:385` | a `telegram_token=` set to an obviously fake value in a test |

No finding is a live credential, and every one is a string a person reviewing the code would want to look at once. There are no false positives in the sense of "identifier mistaken for a secret".

**What changed after the first run.** The first run flagged 20 findings in the standard library and 15 in the third-party code. 19 and 8 of them were identifiers assigned to names that merely contain `token`, `secret` or `pwd`: `token_type = 'quoted-string'` (17 times in the email package), `'pwd': 'pwd#module-pwd'`, `libsecret-1-0`, `SeAssignPrimaryTokenPrivilege`, `IPython.core.magics.osm:OSMagics`, and a variable containing `fake`. That led to the structure checks and to adding `fake` and `mock` to the placeholder words.

**Why the first two rows are not independent.** The filters were tuned after reading those findings, so zero false positives there says the filters work on the cases that motivated them. The third row (my own code) was scanned after the tuning and was not used to tune anything; it is the closest thing here to a blind test, with the obvious weakness that it is my own code.

## 4. Speed

| Scan | Size | Result |
|---|---|---|
| working tree | CPython stdlib, 300k lines | 120,000 to 160,000 lines/s, one thread (several runs) |
| working tree, without the keyword prefilter | same | 82,000 to 89,000 lines/s: the prefilter is worth 1.4x to 1.9x |
| `--history` | 2,000 commits, 200,000 added lines | about 2.5 s (75,000 lines/s, git included) |
| `--history` | 500 commits of 400 lines | about 2.7 s |

The history repository is synthetic (`tools/bench_history.py`): every commit adds 100 lines of generated code, so it measures the cost of reading and scanning diffs, not the behaviour of a repository with large binary files or very long lines. Times vary by about 20% between runs.

## Bugs the tests found while writing it

They are listed because they are what a reviewer should know the test suite is for:

- A diff line that merely *looks* like a file header (an added line `++ x` shows up as `+++ x`) made the parser forget the file name and drop every following line of the hunk, so a secret placed right after it in a commit would not be reported. The parser now follows the hunk's line counts. Test: `test_secret_after_a_header_lookalike_is_still_found`.
- Stopping the history iterator early left `git log` running. The process is now always terminated and waited for.
- SendGrid keys ending in `-` were missed by a trailing `\b` (12 of 600 in the first measurement). Test: `test_tokens_are_found_whatever_character_they_end_with`.
- A repository could name a `textconv` program in its own configuration and have the scanner run it. Test: `test_scanning_never_runs_commands_configured_in_the_repository`.
- A symbolic link inside a repository could make the scanner read files outside it. Test: `test_symbolic_links_are_never_followed`.
