# rag-shield

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://github.com/habib-analyst/rag-shield)
[![GitHub stars](https://img.shields.io/github/stars/habib-analyst/rag-shield.svg)](https://github.com/habib-analyst/rag-shield)

An offline prompt-injection / poisoned-document detector for RAG corpora. Zero dependencies, zero model downloads, zero API keys — pure stdlib heuristics you run on any machine before untrusted documents enter your index.

## Quickstart

```bash
git clone https://github.com/habib-analyst/rag-shield
cd rag-shield

# See it work immediately — generates 16 synthetic attacks + 2 benign
# controls, scans them, prints the detection table:
python -m ragshield demo

# Generate your own labeled attack corpus for testing:
python -m ragshield redteam --out ./attack_corpus -n 20

# Scan a real corpus:
python -m ragshield scan ./corpus --format md --out report.md
python -m ragshield scan ./corpus.jsonl --format json --out report.json
```

`scan` exits nonzero when any document is MALICIOUS, so it drops straight into CI pipelines. `.pdf` files are supported when `pypdf` is installed (optional; everything else is stdlib-only).

## Measured results

Actual output of `python -m ragshield demo` (16 synthetic attacks across 8 attack classes + 2 benign controls — a normal README-like doc and an academic discussion of prompt injection):

| Corpus | Count | Result |
|---|---|---|
| Synthetic attacks | 16 | 16 detected as MALICIOUS (16/16) |
| Benign controls | 2 | 0 flagged MALICIOUS (scores 0.175, 0.000 — both CLEAN) |

```
attacks detected: 16/16 (16 malicious, 0 suspicious)
benign docs flagged MALICIOUS: 0/2
DEMO RESULT: PASS
```

## How it works

Six detectors score each document and an ensemble combines them with a weighted sum, capped at 1.0:

1. **instruction_override** — "ignore previous instructions", and similar phrases
2. **role_confusion** — `[SYSTEM]`, `### Instruction:`, DAN-style prompts
3. **exfiltration_bait** — URLs/emails paired with data-movement verbs
4. **hidden_text** — zero-width characters, HTML comments, CSS hiding
5. **imperative_density** — statistical: imperative-verb ratio
6. **obfuscation** — base64/hex blobs, decoded and rescanned

Verdicts: CLEAN (< 0.28), SUSPICIOUS (≥ 0.28), MALICIOUS (≥ 0.55). Every detector returns a 0–1 score plus the exact evidence spans that produced it, so verdicts are auditable — you see *why* a document was flagged, not just a number.

## Honest limitations

- **Heuristic baseline, not a silver bullet.** Pattern + statistics detectors catch known attack shapes; a determined adversary using novel phrasing, paraphrase, or low-and-slow multi-document poisoning can evade them. Use rag-shield as one layer alongside instruction hierarchies, sandboxing, and output monitoring.
- **English-focused.** Override/role patterns are English; multilingual injection (e.g. transliterated Urdu/Arabic-script variants) is out of scope for v0.1.
- **Academic-discussion false positives.** Documents that *discuss* prompt injection (papers, these very docs) contain attack phrases; rag-shield discounts quoted/discussed phrases via academic-framing detection, but dense quotations of raw payloads may still land SUSPICIOUS — review, don't auto-block.

## License

MIT © 2026 Habib Ur Rehman

---
Built by [Habib Ur Rehman](https://github.com/habib-analyst) · ML/AI Engineer & healthcare-AI researcher ·
[LinkedIn](https://www.linkedin.com/in/hur-dev) · [habib.top](https://habib.top)
