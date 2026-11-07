# Security notes

## What secscan handles, and how

A scanner holds exactly the thing it hunts. These are its rules.

- **A secret is never printed, logged or written.** `Finding.redacted` shows the public prefix of fixed-format tokens (`ghp_`, `AKIA`, `sk_live_`) and asterisks for the rest, and a password-like value shows nothing at all. There is no `--show-secrets` option and no verbose mode that prints more. The secret field is excluded from the object's `repr`, so it does not appear in a traceback or a debug print either. Tests feed every rule a credential and assert that it is absent from text, JSON and SARIF output, from the baseline and from hook output.
- **Memory only.** A secret exists as a Python string while a line is analysed and is dropped with the finding.
- **Baselines hold fingerprints, not secrets**: the rule, the path and a 96-bit BLAKE2b hash of the secret. See "Baseline files" below for what that does and does not protect.
- **No network.** secscan never contacts a provider, so it cannot leak a key by testing it. It also cannot tell you whether a key is still live: assume it is.

## Scanning a repository you do not trust

Reviewing someone else's repository is a normal use, and a repository is attacker-controlled input.

| Risk | What secscan does |
|---|---|
| git runs a program named in the repository's configuration (`diff.<name>.textconv` selected by `.gitattributes`, an `fsmonitor` hook) | git is invoked with `--no-textconv`, `--no-ext-diff` and `core.fsmonitor=false`. A test builds a repository whose `textconv` writes a marker file and checks that neither `--staged` nor `--history` ever runs it |
| a symbolic link points at `~/.ssh/id_rsa` or another file outside the repository | links are never followed; the file is counted as skipped |
| a diff line imitates a file header to make the parser lose track | the parser counts the lines of each hunk from its `@@` header instead of trusting line prefixes |
| a huge file, a minified bundle or a binary | files above 1 MiB (configurable) and binaries (a NUL byte in the first 8 KB) are skipped, and only the first 20,000 characters of a line are scanned |
| shell injection through file names or arguments | git is run with an argument list, never through a shell; names are read from `git ls-files -z` |
| a malformed baseline | rejected with an error (exit 2), never partially applied |

Residual risk: git itself. A repository that exploits a bug in git can still affect any tool that runs git. For a repository you really do not trust, use the Docker image (`--network none --read-only`, non-root user, capabilities dropped, repository mounted read-only), which is what CI exercises.

## Baseline files

A fingerprint is `rule:path:hash(secret)`. It is not reversible for a random 40-character token, but **a guessable secret can be recovered from its hash by trying guesses**, and BLAKE2b is fast by design. So:

- Do not publish a baseline that covers a real, weak, still-valid credential. Rotate it instead of baselining it.
- A baseline of test fixtures and examples, the intended use, is harmless to publish.

## Hooks are not enforcement

- `.git/hooks` is not part of a clone, so each developer must install the hook.
- `git commit --no-verify` skips it.

The hook is a convenience that catches the mistake early. The backstop is CI: [`self-scan.yml`](../.github/workflows/self-scan.yml) scans the working tree and the whole history on every push and pull request, and a server-side pre-receive hook is the only real enforcement. GitHub's own push protection complements this: secscan works offline, on any git host, on history and on formats and generic patterns push protection does not cover.

## If it finds a real secret

1. **Revoke or rotate it now.** Everything else is secondary: if it was ever pushed, assume it has been copied. A secret in a *local* commit that was never pushed is still worth rotating if you cannot be sure.
2. Look in the provider's audit log for use you do not recognise.
3. Remove it from the code and load it from the environment or a secrets manager.
4. Optionally rewrite history (`git filter-repo --replace-text`), force-push, and ask the host to purge cached views. Forks and existing clones keep the old commits, which is why step 1 comes first.
5. Add the cause to the process: install the hook, keep `secscan scan --history` in CI.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
