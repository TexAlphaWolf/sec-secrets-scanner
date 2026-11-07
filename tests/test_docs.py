"""The documentation must not drift away from the code."""

import re
from pathlib import Path

import pytest

from secscan.rules import RULES

ROOT = Path(__file__).resolve().parent.parent
MARKDOWN = [
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "CHANGELOG.md",
]
MARKDOWN += sorted((ROOT / "docs").glob("*.md"))


def test_every_rule_is_documented():
    text = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    missing = [r.id for r in RULES if f"`{r.id}`" not in text]
    assert missing == []


NUMBER_WORDS = {20: "Twenty"}


def test_readme_states_the_real_number_of_rules():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"{len(RULES)} rules" in text


def test_limitations_state_the_real_number_of_rules():
    word = NUMBER_WORDS.get(len(RULES))
    assert word is not None, "update NUMBER_WORDS and docs/limitations.md for the new rule count"
    assert f"**{word} rules only**" in (ROOT / "docs" / "limitations.md").read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize("path", MARKDOWN, ids=lambda p: p.name)
def test_relative_links_point_at_files_that_exist(path):
    text = path.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        file_part = target.split("#", 1)[0]
        assert (path.parent / file_part).exists(), f"{path.name}: broken link {target}"


def test_workflows_referenced_by_the_readme_exist():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for name in re.findall(r"actions/workflows/([\w.-]+\.yml)", text):
        assert (ROOT / ".github" / "workflows" / name).exists(), name
