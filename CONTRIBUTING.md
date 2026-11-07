# Contributing

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\python.exe -m ...
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest --cov
python tools/evaluate.py --corpus /usr/lib/python3.13
python tools/bench_history.py
secscan scan .                                     # the repository must scan clean
```

- Standard library only for the package.
- **Nothing that prints, logs or stores a secret.** A new output path needs a test that feeds it a credential and asserts the credential is absent.
- **No literal credentials in the repository**, not even fake ones: build them at run time in `tests/fakes.py` or `tools/evaluate.py`. A literal that must stay (a header line, a prefix) gets a trailing `# secscan:ignore`.
- **Anything that runs git must stay safe on an untrusted repository**: no shell, fixed arguments, `--no-textconv` and `--no-ext-diff`, no following of links. A change there needs a test with a hostile repository.
- A new rule: [docs/rules.md](docs/rules.md#adding-a-rule). A filter change must keep `tools/evaluate.py` at 0 benign lines flagged and recall of 99.5% or more; CI fails otherwise. Add a test line for the case it fixes.
