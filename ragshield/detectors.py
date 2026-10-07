"""Offline heuristic detectors for prompt-injection in RAG documents.

Every detector is pure stdlib (regex + string statistics), needs no model
downloads and no API keys. Each detector returns a :class:`Detection` with a
0-1 suspicion score and the exact evidence spans that produced it, so every
verdict is auditable.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    """A single suspicious span inside the scanned text."""
    text: str
    start: int
    end: int

    def to_dict(self) -> dict:
        return {"text": self.text, "start": self.start, "end": self.end}


@dataclass
class Detection:
    name: str
    score: float  # 0.0 (clean) .. 1.0 (certain)
    evidence: list[Evidence] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "score": round(self.score, 3),
            "description": self.description,
            "evidence": [e.to_dict() for e in self.evidence],
        }


class BaseDetector:
    name = "base"
    description = ""

    def detect(self, text: str) -> Detection:  # pragma: no cover - interface
        raise NotImplementedError


def _find_all(pattern: re.Pattern, text: str, limit: int = 12) -> list[Evidence]:
    out: list[Evidence] = []
    for m in pattern.finditer(text):
        out.append(Evidence(text=m.group(0), start=m.start(), end=m.end()))
        if len(out) >= limit:
            break
    return out


def _score_for_hits(n: int, per_hit: float, base: float = 0.0, cap: float = 1.0) -> float:
    if n <= 0:
        return 0.0
    return min(cap, base + per_hit * n)


# --------------------------------------------------------------------------- #
# 1. Instruction-override patterns
# --------------------------------------------------------------------------- #
_OVERRIDE_PATTERNS = [
    # (regex, weight) — weight is informational; scoring is count-based
    r"ignore\s+(all\s+)?(your\s+)?(previous|prior|earlier)\s+instructions?",
    r"disregard\s+(all\s+)?(your\s+)?(previous|prior|earlier|the\s+above)\s+instructions?",
    r"forget\s+(your|all\s+of\s+your)\s+instructions?",
    r"override\s+(your\s+)?(system\s+prompt|instructions?|directives?)",
    r"you\s+are\s+now\s+(operating\s+under|following|in)",
    r"from\s+now\s+on[,\s]",
    r"new\s+(system\s+)?instructions?\s*[:]",
    r"do\s+not\s+follow\s+(your\s+)?(previous|prior|original|system)\s+(instructions?|prompt)",
    r"follow\s+these\s+instructions?\s+instead",
    r"instead\s+of\s+following\s+(your|the)\s+(previous|original)",
    r"you\s+must\s+(obey|comply\s+with|follow)\s+(these|the\s+following|my)",
    r"do\s+exactly\s+as\s+i\s+say",
    r"your\s+(real|true|actual|hidden|secret)\s+(instructions?|prompt|directive|orders)",
    r"system\s+prompt",
    r"developer\s+(instructions?|message|directives?)",
    r"confidential\s+directive",
]

# Words that signal the text is *about* prompt injection (academic / defensive
# discussion) rather than *performing* it. When these dominate and the matched
# phrases sit inside quotes, the score is discounted so research write-ups are
# not flagged as attacks.
_ACADEMIC_MARKERS = re.compile(
    r"\b(research|researchers?|paper|study|studies|survey|attack|attacks|"
    r"threat\s+model|defense|defence|mitigation|example|examples|academic|"
    r"evaluation|benchmark|quoted|quotation|demonstrat\w+|analy[sz]\w+)\b",
    re.IGNORECASE,
)


class InstructionOverrideDetector(BaseDetector):
    """Direct attempts to override the model's instructions."""

    name = "instruction_override"
    description = (
        "Matches explicit instruction-override phrasing such as "
        "'ignore previous instructions' or 'you are now following new instructions'."
    )

    def __init__(self) -> None:
        self._patterns = [re.compile(p, re.IGNORECASE) for p in _OVERRIDE_PATTERNS]

    def _academic_discount(self, text: str, evidence: list[Evidence]) -> float:
        markers = len(_ACADEMIC_MARKERS.findall(text))
        if markers < 2 or not evidence:
            return 1.0
        # Discount only when the matched phrases look quoted / discussed.
        quoted = sum(
            1
            for e in evidence
            if re.search(r"[\"'“”`]", text[max(0, e.start - 3): e.end + 3])
        )
        if quoted >= max(1, len(evidence) // 2):
            return 0.35
        return 0.7 if markers >= 4 else 1.0

    def detect(self, text: str) -> Detection:
        evidence: list[Evidence] = []
        for pat in self._patterns:
            evidence.extend(_find_all(pat, text))
        score = _score_for_hits(len(evidence), per_hit=0.22, base=0.28)
        score *= self._academic_discount(text, evidence)
        return Detection(
            name=self.name,
            score=round(min(1.0, score), 3),
            evidence=evidence,
            description=self.description,
        )


# --------------------------------------------------------------------------- #
# 2. Role confusion
# --------------------------------------------------------------------------- #
_ROLE_PATTERNS = [
    r"as\s+an?\s+ai\b",
    r"as\s+a\s+(large\s+)?language\s+model",
    r"\bdeveloper\s+mode\b",
    r"\bjailbreak\w*\b",
    r"\bDAN\b",
    r"\[\s*system\s*\]",
    r"<<\s*SYS\s*>>",
    r"<\|\s*system\s*\|>",
    r"<\|\s*im_start\s*\|>",
    r"###\s*(instruction|system|prompt|developer)\s*:",
    r"you\s+are\s+(chatgpt|an?\s+ai\s+assistant|meta\s+ai|claude|gemini)",
    r"pretend\s+(to\s+be|you\s+are)",
    r"roleplay\s+as\b",
    r"act\s+as\s+(a\s+|an\s+|the\s+)?(system|developer|administrator|admin|root)\b",
    r"simulate\s+(a\s+)?(system|developer|admin)\s+(message|prompt|role)",
]


class RoleConfusionDetector(BaseDetector):
    """Fake roles, fake system delimiters, jailbreak personas."""

    name = "role_confusion"
    description = (
        "Matches role-confusion tricks: jailbreak personas ('DAN', 'developer mode'), "
        "fake system delimiters ([SYSTEM], <|system|>, ### Instruction:) and "
        "impersonation of the assistant's identity."
    )

    def __init__(self) -> None:
        self._patterns = [re.compile(p, re.IGNORECASE) for p in _ROLE_PATTERNS]

    def detect(self, text: str) -> Detection:
        evidence: list[Evidence] = []
        for pat in self._patterns:
            evidence.extend(_find_all(pat, text))
        return Detection(
            name=self.name,
            score=round(_score_for_hits(len(evidence), per_hit=0.25, base=0.30), 3),
            evidence=evidence,
            description=self.description,
        )


# --------------------------------------------------------------------------- #
# 3. Exfiltration bait
# --------------------------------------------------------------------------- #
_URL_RE = re.compile(r"https?://[^\s)>\]\"']+|www\.[^\s)>\]\"']+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_DATA_VERBS = re.compile(
    r"\b(send|post|upload|transmit|exfiltrate|leak|forward|email|e-mail|"
    r"share|submit|dispatch|relay|push|export)\b",
    re.IGNORECASE,
)
_SENSITIVE_NOUNS = re.compile(
    r"\b(password|passwd|api[\s_-]?key|secret|secrets|access[\s_-]?token|"
    r"auth[\s_-]?token|private[\s_-]?key|ssn|social\s+security|credit\s+card|"
    r"bank\s+account|credentials)\b",
    re.IGNORECASE,
)
_WEBHOOK_RE = re.compile(r"\b(webhook|callback\s+url|exfil\w*)\b", re.IGNORECASE)


class ExfiltrationBaitDetector(BaseDetector):
    """Instructions to ship data out: URL/email + imperative data verb."""

    name = "exfiltration_bait"
    description = (
        "Flags instructions that pair an exfiltration target (URL, email, webhook) "
        "with a data-movement verb (send, post, upload, ...) or that request "
        "sensitive credentials."
    )

    def _near(self, text: str, span: tuple[int, int], pattern: re.Pattern,
              window: int = 140) -> list[Evidence]:
        lo, hi = max(0, span[0] - window), min(len(text), span[1] + window)
        return _find_all(pattern, text[lo:hi])

    def detect(self, text: str) -> Detection:
        evidence: list[Evidence] = []
        score = 0.0

        urls = list(_URL_RE.finditer(text))
        emails = list(_EMAIL_RE.finditer(text))
        for m in urls + emails:
            nearby_verbs = self._near(text, (m.start(), m.end()), _DATA_VERBS)
            if nearby_verbs:
                score = max(score, 0.9)
                evidence.append(Evidence(m.group(0), m.start(), m.end()))
                evidence.extend(
                    Evidence(v.text, v.start, v.end) for v in nearby_verbs[:3]
                )
            elif _WEBHOOK_RE.search(m.group(0)):
                score = max(score, 0.7)
                evidence.append(Evidence(m.group(0), m.start(), m.end()))

        for m in _SENSITIVE_NOUNS.finditer(text):
            nearby_verbs = self._near(text, (m.start(), m.end()), _DATA_VERBS)
            if nearby_verbs:
                score = max(score, 0.75)
                evidence.append(Evidence(m.group(0), m.start(), m.end()))

        if not evidence and (urls or emails):
            # A bare URL/email with no data verb is only weakly suspicious.
            score = max(score, 0.12)
            first = (urls + emails)[0]
            evidence.append(Evidence(first.group(0), first.start(), first.end()))

        return Detection(
            name=self.name,
            score=round(min(1.0, score), 3),
            evidence=evidence[:12],
            description=self.description,
        )


# --------------------------------------------------------------------------- #
# 4. Hidden-text tricks
# --------------------------------------------------------------------------- #
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_CSS_HIDE_RE = re.compile(
    r"(font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|"
    r"color\s*:\s*(white|#fff(fff)?)\s*;?\s*background(-color)?\s*:\s*(white|#fff(fff)?))",
    re.IGNORECASE,
)
_MD_EMPTY_LINK_RE = re.compile(r"\[[^\]]{0,3}\]\(\s*[^)]+\)")


class HiddenTextDetector(BaseDetector):
    """Zero-width chars, HTML comments, CSS-hiding, sneaky markdown links."""

    name = "hidden_text"
    description = (
        "Flags text hidden from human readers but visible to the model: "
        "zero-width characters (U+200B-U+200D, U+FEFF), HTML comments, "
        "CSS hiding tricks and empty-text markdown links."
    )

    def detect(self, text: str) -> Detection:
        evidence: list[Evidence] = []
        score = 0.0

        zw = _find_all(_ZERO_WIDTH_RE, text, limit=20)
        if zw:
            score = max(score, 0.75 if len(zw) >= 3 else 0.45)
            evidence.extend(zw[:8])

        for m in _HTML_COMMENT_RE.finditer(text):
            inner = m.group(1)
            inner_hits = (
                len(_DATA_VERBS.findall(inner))
                + sum(1 for p in _OVERRIDE_PATTERNS if re.search(p, inner, re.IGNORECASE))
            )
            if inner_hits:
                score = max(score, 0.8)
            else:
                score = max(score, 0.3)
            evidence.append(Evidence(m.group(0)[:120], m.start(), m.end()))
            if len(evidence) >= 12:
                break

        css = _find_all(_CSS_HIDE_RE, text)
        if css:
            score = max(score, 0.7)
            evidence.extend(css)

        md = _find_all(_MD_EMPTY_LINK_RE, text)
        if md:
            score = max(score, 0.4)
            evidence.extend(md)

        return Detection(
            name=self.name,
            score=round(min(1.0, score), 3),
            evidence=evidence[:12],
            description=self.description,
        )


# --------------------------------------------------------------------------- #
# 5. Imperative-density (statistical)
# --------------------------------------------------------------------------- #
_IMPERATIVE_VERBS = frozenset(
    """
    ignore disregard forget obey comply follow execute run delete download install
    send post upload transmit exfiltrate leak forward email share submit click open
    visit reveal disclose output print return provide give tell answer respond act
    pretend assume remember ensure summarise summarize translate repeat continue
    stop start refuse deny bypass circumvent override
    """.split()
)
_WORD_RE = re.compile(r"[A-Za-z']+")


class ImperativeDensityDetector(BaseDetector):
    """Statistical signal: fraction of tokens that are imperative verbs.

    Normal prose sits around 1-3%; instruction payloads often exceed 8%.
    """

    name = "imperative_density"
    description = (
        "Statistical detector: measures the ratio of imperative verbs to total "
        "words. Benign prose is ~1-3%; dense command text scores high."
    )
    baseline = 0.035
    scale = 0.10  # density at baseline+scale maps to ~1.0

    def detect(self, text: str) -> Detection:
        words = _WORD_RE.findall(text.lower())
        if len(words) < 20:
            return Detection(self.name, 0.0, [], self.description)
        hits = sum(1 for w in words if w in _IMPERATIVE_VERBS)
        density = hits / len(words)
        score = max(0.0, min(1.0, (density - self.baseline) / self.scale))
        evidence = (
            [Evidence(f"imperative density {density:.1%} ({hits}/{len(words)} words)",
                      0, min(len(text), 60))]
            if score > 0
            else []
        )
        return Detection(self.name, round(score, 3), evidence, self.description)


# --------------------------------------------------------------------------- #
# 6. Obfuscation: base64 / hex blobs, decoded and rescanned
# --------------------------------------------------------------------------- #
_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")
_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s:]?){24,}\b")


class ObfuscationDetector(BaseDetector):
    """Long base64/hex blobs; decoded payload is rescanned for injections."""

    name = "obfuscation"
    description = (
        "Flags long base64/hex blobs. Decodable blobs are decoded and rescanned "
        "with the instruction-override patterns — a decoded injection is a "
        "near-certain attack."
    )

    def __init__(self) -> None:
        self._override = InstructionOverrideDetector()
        self._verbs = _DATA_VERBS

    def _try_b64(self, blob: str) -> str | None:
        try:
            raw = base64.b64decode(blob, validate=True)
            txt = raw.decode("utf-8", errors="strict")
            if sum(c.isprintable() or c.isspace() for c in txt) / max(len(txt), 1) > 0.9:
                return txt
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None
        return None

    def _try_hex(self, blob: str) -> str | None:
        try:
            cleaned = re.sub(r"[\s:]", "", blob)
            raw = bytes.fromhex(cleaned)
            txt = raw.decode("utf-8", errors="strict")
            if sum(c.isprintable() or c.isspace() for c in txt) / max(len(txt), 1) > 0.9:
                return txt
        except (ValueError, UnicodeDecodeError):
            return None
        return None

    def detect(self, text: str) -> Detection:
        evidence: list[Evidence] = []
        score = 0.0

        for m in _B64_RE.finditer(text):
            blob = m.group(0)
            decoded = self._try_b64(blob)
            if decoded is None:
                continue
            sub = self._override.detect(decoded)
            verbs = bool(self._verbs.search(decoded))
            if sub.score >= 0.3 or verbs:
                score = max(score, 0.95)
                evidence.append(Evidence(
                    f"base64 blob decodes to injection payload: {decoded[:100]!r}",
                    m.start(), m.end()))
            else:
                score = max(score, 0.45)
                evidence.append(Evidence(
                    f"decodable base64 blob ({len(blob)} chars): {blob[:40]}...",
                    m.start(), m.end()))
            if len(evidence) >= 8:
                break

        for m in _HEX_RE.finditer(text):
            blob = m.group(0)
            decoded = self._try_hex(blob)
            if decoded is None:
                continue
            sub = self._override.detect(decoded)
            if sub.score >= 0.3:
                score = max(score, 0.95)
                evidence.append(Evidence(
                    f"hex blob decodes to injection payload: {decoded[:100]!r}",
                    m.start(), m.end()))
            else:
                score = max(score, 0.4)
                evidence.append(Evidence(
                    f"decodable hex blob ({len(blob)} chars)", m.start(), m.end()))
            if len(evidence) >= 12:
                break

        return Detection(self.name, round(min(1.0, score), 3),
                         evidence[:12], self.description)


# --------------------------------------------------------------------------- #
# Ensemble registry
# --------------------------------------------------------------------------- #
#: (detector class, ensemble weight). Weighted sum is capped at 1.0.
DETECTORS: list[tuple[type[BaseDetector], float]] = [
    (InstructionOverrideDetector, 1.0),
    (RoleConfusionDetector, 0.7),
    (ExfiltrationBaitDetector, 0.9),
    (HiddenTextDetector, 0.8),
    (ImperativeDensityDetector, 0.5),
    (ObfuscationDetector, 0.9),
]


def build_detectors() -> list[tuple[BaseDetector, float]]:
    return [(cls(), weight) for cls, weight in DETECTORS]


def ensemble_score(detections: list[Detection],
                   weights: list[float] | None = None) -> float:
    """Weighted-sum ensemble, capped at 1.0."""
    if weights is None:
        weights = [w for _, w in DETECTORS]
    total = sum(d.score * w for d, w in zip(detections, weights))
    return round(min(1.0, total), 3)


__all__ = [
    "Evidence", "Detection", "BaseDetector",
    "InstructionOverrideDetector", "RoleConfusionDetector",
    "ExfiltrationBaitDetector", "HiddenTextDetector",
    "ImperativeDensityDetector", "ObfuscationDetector",
    "DETECTORS", "build_detectors", "ensemble_score",
]
