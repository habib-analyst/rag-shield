"""Corpus scanner: runs the detector ensemble over documents, emits verdicts."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .detectors import Detection, build_detectors, ensemble_score

MALICIOUS_THRESHOLD = 0.55
SUSPICIOUS_THRESHOLD = 0.28

SUPPORTED_SUFFIXES = {".txt", ".md", ".markdown", ".jsonl"}


@dataclass
class ScanResult:
    doc_id: str
    score: float
    verdict: str  # CLEAN | SUSPICIOUS | MALICIOUS
    detections: list[Detection] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "doc_id": self.doc_id,
            "score": self.score,
            "verdict": self.verdict,
            "error": self.error,
            "detections": [d.to_dict() for d in self.detections],
        }


def verdict_for(score: float) -> str:
    if score >= MALICIOUS_THRESHOLD:
        return "MALICIOUS"
    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "CLEAN"


class Scanner:
    def __init__(self) -> None:
        self.detectors = build_detectors()

    def scan_text(self, doc_id: str, text: str) -> ScanResult:
        detections = [det.detect(text) for det, _ in self.detectors]
        weights = [w for _, w in self.detectors]
        score = ensemble_score(detections, weights)
        return ScanResult(doc_id=doc_id, score=score,
                          verdict=verdict_for(score), detections=detections)

    def _read_pdf(self, path: Path) -> str:
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise RuntimeError(
                f"pypdf is not installed; cannot read {path.name}. "
                "Install it with: pip install pypdf"
            ) from exc
        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)

    def _read_doc(self, path: Path) -> str:
        if path.suffix.lower() == ".pdf":
            return self._read_pdf(path)
        return path.read_text(encoding="utf-8", errors="replace")

    def scan_file(self, path: Path) -> ScanResult:
        try:
            text = self._read_doc(path)
        except Exception as exc:  # unreadable file -> error result, not a crash
            return ScanResult(doc_id=str(path), score=0.0, verdict="CLEAN",
                              error=str(exc))
        return self.scan_text(str(path), text)

    def scan_jsonl(self, path: Path) -> list[ScanResult]:
        results: list[ScanResult] = []
        with path.open(encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as exc:
                    results.append(ScanResult(
                        doc_id=f"{path}#line{i}", score=0.0, verdict="CLEAN",
                        error=f"bad JSON: {exc}"))
                    continue
                doc_id = str(obj.get("id", f"{path}#line{i}"))
                results.append(self.scan_text(doc_id, str(obj.get("text", ""))))
        return results

    def scan_path(self, target: Path) -> list[ScanResult]:
        """Scan a file, a directory of documents, or a .jsonl corpus."""
        target = Path(target)
        if target.is_file():
            if target.suffix.lower() == ".jsonl":
                return self.scan_jsonl(target)
            return [self.scan_file(target)]
        results: list[ScanResult] = []
        for path in sorted(target.rglob("*")):
            if not path.is_file() or path.name.startswith("."):
                continue
            if path.suffix.lower() in SUPPORTED_SUFFIXES or path.suffix.lower() == ".pdf":
                results.append(self.scan_file(path))
        return results


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
def _verdict_emoji(verdict: str) -> str:
    return {"MALICIOUS": "🔴", "SUSPICIOUS": "🟡", "CLEAN": "🟢"}.get(verdict, "⚪")


def json_report(results: list[ScanResult]) -> str:
    summary = {
        "total": len(results),
        "malicious": sum(r.verdict == "MALICIOUS" for r in results),
        "suspicious": sum(r.verdict == "SUSPICIOUS" for r in results),
        "clean": sum(r.verdict == "CLEAN" for r in results),
    }
    return json.dumps({"summary": summary,
                       "results": [r.to_dict() for r in results]}, indent=2)


def markdown_report(results: list[ScanResult], title: str = "rag-shield scan report") -> str:
    total = len(results)
    mal = sum(r.verdict == "MALICIOUS" for r in results)
    sus = sum(r.verdict == "SUSPICIOUS" for r in results)
    lines = [
        f"# {title}",
        "",
        f"Scanned **{total}** documents: 🔴 {mal} malicious, "
        f"🟡 {sus} suspicious, 🟢 {total - mal - sus} clean.",
        "",
        "| Document | Score | Verdict | Top signals |",
        "|---|---|---|---|",
    ]
    for r in results:
        top = ", ".join(
            f"{d.name} ({d.score:.2f})"
            for d in sorted(r.detections, key=lambda d: d.score, reverse=True)[:2]
            if d.score > 0
        ) or "—"
        lines.append(f"| `{r.doc_id}` | {r.score:.3f} | "
                     f"{_verdict_emoji(r.verdict)} {r.verdict} | {top} |")
    lines.append("")
    for r in results:
        if r.verdict == "CLEAN" and not r.error:
            continue
        lines.append(f"## {_verdict_emoji(r.verdict)} `{r.doc_id}` — "
                     f"score {r.score:.3f}")
        if r.error:
            lines.append(f"_Error: {r.error}_")
        for d in sorted(r.detections, key=lambda d: d.score, reverse=True):
            if d.score <= 0:
                continue
            lines.append(f"- **{d.name}** ({d.score:.2f}): {d.description}")
            for e in d.evidence[:4]:
                snippet = e.text.replace("\n", " ")[:110]
                lines.append(f"  - `{snippet}`")
        lines.append("")
    return "\n".join(lines)


__all__ = [
    "Scanner", "ScanResult", "verdict_for", "json_report", "markdown_report",
    "MALICIOUS_THRESHOLD", "SUSPICIOUS_THRESHOLD",
]
