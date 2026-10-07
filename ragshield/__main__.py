"""CLI for rag-shield: scan, redteam, demo."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .redteam import ATTACK_CLASSES, generate, generate_corpus
from .scanner import Scanner, json_report, markdown_report


def cmd_scan(args: argparse.Namespace) -> int:
    scanner = Scanner()
    results = scanner.scan_path(Path(args.target))
    if args.format == "json":
        out = json_report(results)
    else:
        out = markdown_report(results)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"wrote {args.out} ({len(results)} documents)")
    else:
        print(out)
    mal = sum(r.verdict == "MALICIOUS" for r in results)
    print(f"\n{len(results)} docs: "
          f"{mal} malicious, "
          f"{sum(r.verdict == 'SUSPICIOUS' for r in results)} suspicious, "
          f"{sum(r.verdict == 'CLEAN' for r in results)} clean", file=sys.stderr)
    return 1 if mal else 0


def cmd_redteam(args: argparse.Namespace) -> int:
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    if args.attack_class:
        docs = [generate(args.attack_class, seed=args.seed + i)
                for i in range(args.n)]
    else:
        docs = generate_corpus(n=args.n, seed=args.seed)
    for doc in docs:
        (outdir / f"{doc.doc_id}.md").write_text(doc.text, encoding="utf-8")
    print(f"wrote {len(docs)} synthetic attack documents to {outdir}")
    return 0


BENIGN_DOCS = {
    "benign-readme.md": """# VectorStore

A lightweight in-memory vector store for prototyping retrieval pipelines.

## Features

- Stores embeddings alongside document metadata.
- Cosine similarity search with optional top-k filtering.
- Serialization to JSON for small corpora.

## Usage

The library exposes a single `VectorStore` class. Documents are added with
their precomputed embeddings, and queries return ranked matches. The project
is intended for experiments and teaching, not production workloads.

## License

MIT. See LICENSE for details.
""",
    "benign-discussion.md": """# Notes on indirect prompt injection research

Recent work studies a class of attacks in which third-party documents
embedded in retrieval corpora try to steer model behavior. A canonical
example quoted in the literature is the phrase "ignore all previous
instructions", which researchers use to demonstrate how retrieved text can
conflict with system-level directives.

The threat model assumes an attacker can publish content that is later
ingested by a retrieval pipeline. Defenses discussed in these papers include
input sanitization, instruction hierarchies, and detection of anomalous
directives in retrieved context. Evaluation typically measures attack
success rate before and after a proposed mitigation.

References: Greshake et al. (2023) on indirect prompt injection;
survey papers on LLM security published in 2024.
""",
}


def cmd_demo(args: argparse.Namespace) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ragshield-demo-") as tmp:
        corpus = Path(tmp)
        for doc in generate_corpus(n=args.n, seed=1234):
            (corpus / f"{doc.doc_id}.md").write_text(doc.text, encoding="utf-8")
        for name, text in BENIGN_DOCS.items():
            (corpus / name).write_text(text, encoding="utf-8")

        scanner = Scanner()
        results = scanner.scan_path(corpus)

    attacks = [r for r in results
               if Path(r.doc_id).name.startswith("attack-")]
    benign = [r for r in results
              if not Path(r.doc_id).name.startswith("attack-")]
    caught = sum(r.verdict in ("SUSPICIOUS", "MALICIOUS") for r in attacks)
    mal = sum(r.verdict == "MALICIOUS" for r in attacks)
    benign_flagged = [r for r in benign if r.verdict == "MALICIOUS"]

    print("=" * 78)
    print("rag-shield demo: synthetic attack corpus + benign controls")
    print("=" * 78)
    print(f"{'document':42s} {'score':>6s}  verdict")
    print("-" * 78)
    for r in sorted(results, key=lambda r: r.doc_id):
        short = r.doc_id if len(r.doc_id) <= 40 else r.doc_id[:37] + "..."
        mark = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟡", "CLEAN": "🟢"}[r.verdict]
        print(f"{short:42s} {r.score:6.3f}  {mark} {r.verdict}")
    print("-" * 78)
    print(f"attacks detected: {caught}/{len(attacks)} "
          f"({mal} malicious, {caught - mal} suspicious)")
    print(f"benign docs flagged MALICIOUS: {len(benign_flagged)}/{len(benign)}")
    if benign_flagged:
        print("  FLAGGED:", ", ".join(r.doc_id for r in benign_flagged))
    print("=" * 78)
    ok = caught == len(attacks) and not benign_flagged
    print("DEMO RESULT:", "PASS ✅" if ok else "CHECK ⚠️")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rag-shield",
                                description="Offline prompt-injection detector "
                                            "for RAG corpora.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a folder of documents or a JSONL corpus.")
    s.add_argument("target", help="Directory, document file, or .jsonl corpus")
    s.add_argument("--format", choices=["md", "json"], default="md")
    s.add_argument("--out", default=None, help="Write report to this file")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("redteam", help="Generate synthetic attack documents.")
    r.add_argument("--out", default="./attack_corpus")
    r.add_argument("-n", type=int, default=20)
    r.add_argument("--attack-class", choices=ATTACK_CLASSES, default=None)
    r.add_argument("--seed", type=int, default=42)
    r.set_defaults(func=cmd_redteam)

    d = sub.add_parser("demo", help="Generate attacks, scan them, print results.")
    d.add_argument("-n", type=int, default=16,
                   help="Number of synthetic attacks to generate")
    d.set_defaults(func=cmd_demo)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
