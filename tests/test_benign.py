"""Benign controls: normal docs and academic discussion must not be MALICIOUS."""
from pathlib import Path

import pytest

from ragshield import Scanner
from ragshield.__main__ import BENIGN_DOCS

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def scanner():
    return Scanner()


def test_readme_fixture_clean(scanner):
    text = (FIXTURES / "benign_readme.md").read_text()
    result = scanner.scan_text("benign_readme", text)
    assert result.verdict == "CLEAN", (
        f"score={result.score}, "
        f"fired={[ (d.name, d.score) for d in result.detections if d.score > 0 ]}"
    )


def test_academic_discussion_not_malicious(scanner):
    text = (FIXTURES / "academic_discussion.md").read_text()
    result = scanner.scan_text("academic_discussion", text)
    assert result.verdict != "MALICIOUS", (
        f"score={result.score}, "
        f"fired={[ (d.name, d.score) for d in result.detections if d.score > 0 ]}"
    )


def test_demo_benign_controls_not_malicious(scanner):
    for name, text in BENIGN_DOCS.items():
        result = scanner.scan_text(name, text)
        assert result.verdict != "MALICIOUS", name
