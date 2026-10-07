"""rag-shield: offline prompt-injection / poisoned-document detector for RAG corpora."""

__version__ = "0.1.0"

from .detectors import (
    Detection,
    Evidence,
    build_detectors,
    ensemble_score,
)
from .scanner import (
    Scanner,
    ScanResult,
    json_report,
    markdown_report,
    verdict_for,
)
from .redteam import generate, generate_corpus, ATTACK_CLASSES

__all__ = [
    "__version__",
    "Detection", "Evidence", "build_detectors", "ensemble_score",
    "Scanner", "ScanResult", "json_report", "markdown_report", "verdict_for",
    "generate", "generate_corpus", "ATTACK_CLASSES",
]
