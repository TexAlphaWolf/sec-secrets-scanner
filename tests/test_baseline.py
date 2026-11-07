import json

import pytest

from secscan import baseline
from secscan.baseline import BaselineError
from secscan.scanner import scan_text

from .fakes import samples

SAMPLES = samples()


def findings():
    return scan_text(SAMPLES["github-token"][0] + "\n" + SAMPLES["aws-access-key-id"][0], "a.py")


def test_dump_and_load_roundtrip_without_the_secret(tmp_path):
    path = tmp_path / "b.json"
    assert baseline.dump(findings(), path) == 2
    text = path.read_text()
    assert SAMPLES["github-token"][1] not in text
    assert baseline.load(path) == {f.fingerprint for f in findings()}
    assert json.loads(text)["version"] == 1


def test_dump_is_sorted_and_deduplicated(tmp_path):
    path = tmp_path / "b.json"
    baseline.dump(findings() + findings(), path)
    prints = json.loads(path.read_text())["fingerprints"]
    assert prints == sorted(set(prints))


def test_apply_splits_new_from_known():
    known = {findings()[0].fingerprint}
    fresh, suppressed = baseline.apply(findings(), known)
    assert suppressed == 1
    assert [f.rule_id for f in fresh] == [findings()[1].rule_id]


@pytest.mark.parametrize(
    "content",
    ["not json", "[]", '{"version": 2, "fingerprints": []}', '{"version": 1, "fingerprints": [1]}'],
)
def test_bad_baselines_are_rejected(tmp_path, content):
    path = tmp_path / "b.json"
    path.write_text(content)
    with pytest.raises(BaselineError):
        baseline.load(path)


def test_missing_baseline_is_an_error(tmp_path):
    with pytest.raises(BaselineError, match="cannot read"):
        baseline.load(tmp_path / "nope.json")
