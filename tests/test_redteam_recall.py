"""Recall: every redteam attack class must be caught by its matching detector."""
import pytest

from ragshield.redteam import (
    ATTACK_CLASSES,
    EXPECTED_DETECTOR,
    generate,
    generate_corpus,
)
from ragshield.scanner import Scanner


@pytest.fixture(scope="module")
def scanner():
    return Scanner()


@pytest.mark.parametrize("attack_class", ATTACK_CLASSES)
def test_attack_caught_by_matching_detector(scanner, attack_class):
    doc = generate(attack_class, seed=99)
    result = scanner.scan_text(doc.doc_id, doc.text)
    expected = EXPECTED_DETECTOR[attack_class]
    by_name = {d.name: d for d in result.detections}
    assert by_name[expected].score >= 0.3, (
        f"{attack_class}: expected detector {expected} did not fire "
        f"(scores: {[(d.name, d.score) for d in result.detections]})"
    )
    assert result.verdict in ("SUSPICIOUS", "MALICIOUS"), (
        f"{attack_class}: verdict was {result.verdict}"
    )


def test_corpus_covers_all_classes(scanner):
    docs = generate_corpus(n=16, seed=1)
    classes = {d.attack_class for d in docs}
    assert classes == set(ATTACK_CLASSES)
    missed = [d.doc_id for d in docs
              if scanner.scan_text(d.doc_id, d.text).verdict == "CLEAN"]
    assert not missed, f"attacks missed: {missed}"


def test_attack_docs_are_labeled():
    doc = generate("direct_override", seed=5)
    assert "SYNTHETIC" in doc.text and "attack_class" in doc.text
