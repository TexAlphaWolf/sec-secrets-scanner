import json

from secscan import report
from secscan.rules import RULES
from secscan.scanner import Stats, scan_text

from .fakes import samples

SAMPLES = samples()
LINE, SECRET = SAMPLES["github-token"]
STATS = Stats(files=3, lines=120)


def found():
    return scan_text(LINE, "src/app.py")


def test_text_report_has_location_rule_and_redaction_only():
    out = report.to_text(found(), STATS)
    assert out.startswith("src/app.py:1:10  github-token  ghp_")
    assert SECRET not in out
    assert "1 finding(s) in 1 file(s) (3 files, 120 lines)" in out


def test_text_report_clean_and_with_suppressed():
    assert report.to_text([], STATS) == "No secrets found (3 files, 120 lines)"
    assert "2 suppressed by baseline" in report.to_text([], STATS, suppressed=2)


def test_text_report_shows_short_commit():
    finding = scan_text(LINE, "a.py")[0]
    from dataclasses import replace

    out = report.to_text([replace(finding, commit="0123456789abcdef")], STATS)
    assert "[01234567]" in out


def test_json_report():
    data = json.loads(report.to_json(found(), STATS, suppressed=4))
    assert data["suppressed"] == 4 and data["files"] == 3
    (item,) = data["findings"]
    assert item["rule"] == "github-token" and item["path"] == "src/app.py"
    assert SECRET not in json.dumps(data)
    assert item["fingerprint"].startswith("github-token:src/app.py:")


def test_sarif_is_structurally_valid_and_contains_no_secret():
    raw = report.to_sarif(found())
    sarif = json.loads(raw)
    assert sarif["version"] == "2.1.0"
    (run,) = sarif["runs"]
    assert run["tool"]["driver"]["name"] == "secscan"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {r.id for r in RULES}
    (result,) = run["results"]
    assert result["ruleId"] == "github-token" and result["level"] == "error"
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 1, "startColumn": 10}
    assert "secscan/v1" in result["partialFingerprints"]
    assert SECRET not in raw


def test_sarif_levels_follow_severity():
    medium = scan_text(SAMPLES["generic-secret"][0], "a.py")[0]
    result = json.loads(report.to_sarif([medium]))["runs"][0]["results"][0]
    assert result["level"] == "warning"
