# Limitations

What secscan does not catch, or catches at a cost, with the numbers where there are numbers. A scanner that hides its blind spots is worse than none.

## It looks for known shapes and for quoted assignments

- **Twenty rules only** ([list](rules.md)). A token format that is not in the list is invisible unless it is a quoted value assigned to a name such as `api_key`.
- **The generic rule needs quotes.** `api_key = "..."`, `"password": "..."` and `password: '...'` are found; `password: abc123XYZ789` in YAML and `PASSWORD=abc123XYZ789` in a `.env` file are not, because without quotes the boundary between a value and the rest of the line is guesswork and the false positives are heavy. Formats with a distinctive prefix (`ghp_`, `AKIA`, ...) are found with or without quotes.
- **Names matter.** The generic rule only fires for names containing `secret`, `token`, `password`, `passwd`, `pwd`, `api_key`, `apikey`, `access_key`, `auth_key` or `private_key`. A secret called `salt` or `credential` is not found.
- **A private key is detected by its header line**, not by the body, which is a run of ordinary base64 lines. Removing only the header line hides it.
- **A secret split across lines or built by concatenation** (`"ghp_" + rest`) is not reassembled.
- **Encoded secrets** (base64 of a token, URL-encoded, inside a JSON string with escapes) are not decoded.

## Cost of the filters

The filters that remove false positives also remove some real secrets. Measured on random alphanumeric values assigned to `api_key` (20,000 per length):

| Length | Missed |
|---|---|
| 12 characters | 0.59% |
| 16 characters | 0.20% |
| 24 characters | 0.00% |
| 32 characters | 0.05% |

- The misses are random strings with an unusually repeated alphabet (entropy under the length-scaled floor) or that spell CamelCase words by chance.
- **Passwords that are words are not secrets to the generic rule.** `password = "admin"`, `"test"`, `"changeme"`, `"letmein"` and similar literals are treated as placeholders, as is anything containing `fake`, `mock`, `dummy`, `your` or `example`: a real password containing such a word is missed.
- **Short identifier-shaped values are skipped**: lowercase or mixed-case words joined by `-` or `_` and shorter than 24 characters, such as `correct-horse`. A passphrase of four or more words is longer and is kept; a short one is not.
- **The same filters apply to passwords in URLs** (`scheme://user:password@host`): 0.13% of random 16-character passwords are missed, for the same reasons.
- **Entropy is a heuristic**: a guessable password such as `Summer2024!!` passes the generic rule only because it is long enough and varied enough; a short human-chosen one can fall below the floor.

## Where it does not look

- **Files above 1 MiB** (change with `--max-size`) and **binary files** are skipped, as are common media, archive, font and database extensions and minified `.min.js` / `.min.css` / `.map` files. A secret inside a SQLite file, a ZIP or a source map is not found.
- **Lines are cut at 20,000 characters.** A secret beyond that, in a minified file that was not skipped by name, is not found.
- **Commit messages, branch and tag names and issue text** are not scanned.
- **Git's history views.** `--history` uses `git log --all -p`, which by design shows no diff for merge commits: a secret introduced *only* while resolving a merge conflict is not in the output. Objects that no branch, tag or stash reaches (old reflog entries, dangling commits) are not visited either.
- **The working-tree scan covers tracked and untracked files that are not ignored** (`git ls-files -co --exclude-standard`). A gitignored `.env` is deliberately not reported: it is not going to be committed. Outside a repository it walks the folder and skips `node_modules`, virtual environments and build folders.

## Platform notes

- The git hook is a shell script. On Windows it runs through the `sh` that comes with Git for Windows; the hook test is skipped on Windows because it needs a POSIX shell.
- Symbolic-link and permission tests are skipped on Windows.
- `--history` on a very large repository is limited by git and by Python: about 75,000 added lines per second, so a repository with tens of millions of added lines takes minutes. Run it in CI, not in a hook.

## What it is not

It is not a replacement for revoking leaked keys, for GitHub push protection (which validates some tokens with their provider) or for a secrets manager. It makes the mistake visible before and after it happens; it does not make the secret safe.
