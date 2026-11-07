# Security policy

If you find a vulnerability (for example a way to make secscan print or store a secret, run a program from a scanned repository, read a file outside the repository, or hide a secret from a scan with a crafted diff or file), please use GitHub's **private vulnerability reporting** (Security tab, "Report a vulnerability") instead of a public issue. You will get an answer within a few days.

A secret that secscan fails to detect is a normal bug, not a vulnerability: open an issue with the **format** of the token (never a real one).

Supported: the latest release.

How the project handles secrets and untrusted repositories is in [docs/security.md](docs/security.md).
