"""CLI smoke tests: demo, scan, redteam — no network, temp dirs only."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from ragshield.__main__ import main as cli_main
from ragshield.redteam import generate_corpus


def test_demo_passes():
    assert cli_main(["demo", "-n", "16"]) == 0


def test_demo_python_m():
    proc = subprocess.run(
        [sys.executable, "-m", "ragshield", "demo", "-n", "8"],
        capture_output=True, text=True, cwd=Path(__file__).parent.parent,
    )
    assert proc.returncode == 0, proc.stderr
    assert "DEMO RESULT: PASS" in proc.stdout


def test_scan_directory(tmp_path):
    for doc in generate_corpus(n=4, seed=11):
        (tmp_path / f"{doc.doc_id}.md").write_text(doc.text)
    (tmp_path / "ok.md").write_text("A perfectly ordinary project description.")
    out = tmp_path / "report.md"
    rc = cli_main(["scan", str(tmp_path), "--format", "md", "--out", str(out)])
    assert rc == 1  # malicious docs present -> nonzero exit
    report = out.read_text()
    assert "MALICIOUS" in report


def test_scan_jsonl_json_format(tmp_path):
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text(json.dumps({"id": "d1", "text": "hello world"}) + "\n")
    out = tmp_path / "report.json"
    assert cli_main(["scan", str(corpus), "--format", "json",
                     "--out", str(out)]) == 0
    data = json.loads(out.read_text())
    assert data["summary"]["total"] == 1
    assert data["results"][0]["verdict"] == "CLEAN"


def test_redteam_writes_files(tmp_path):
    out = tmp_path / "attacks"
    assert cli_main(["redteam", "--out", str(out), "-n", "8",
                     "--seed", "3"]) == 0
    assert len(list(out.glob("*.md"))) == 8


def test_redteam_single_class(tmp_path):
    out = tmp_path / "attacks"
    assert cli_main(["redteam", "--out", str(out), "-n", "3",
                     "--attack-class", "exfiltration"]) == 0
    files = list(out.glob("*.md"))
    assert len(files) == 3
    assert "exfiltration" in files[0].read_text()
