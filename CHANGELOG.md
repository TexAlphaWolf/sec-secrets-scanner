# Changelog

## Unreleased

Documentation and measurement only, no change to the scanner: `tools/evaluate.py` now samples the password-in-URL rule as heavily as the generic rule (20,000 values), and the recall figures in the README and `docs/evaluation.md` are corrected (99.84% overall; passwords in URLs 99.87%, not 100%).

## 1.0.0

First release. 20 rules (cloud, source-hosting and package-registry tokens, webhooks, payment and AI provider keys, JWT, private keys, passwords in URLs, a generic quoted-assignment rule) with entropy, placeholder and structure filters. Scans the working tree, the staged changes (as a git hook or for the pre-commit framework) or every commit on every branch. Baselines that store fingerprints only, inline and file-based ignores, text / JSON / SARIF reports that never contain a secret, `install-hook`, a Docker image, a self-scan workflow that uploads SARIF to GitHub code scanning, and tools that measure recall, false positives, real-code findings and speed.

Hardened against hostile repositories: no `textconv`, external diff or `fsmonitor` execution, no symlink following, a diff parser that follows hunk line counts.
