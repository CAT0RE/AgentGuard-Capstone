from __future__ import annotations

import ast
import html
import json
import math
import re
import unicodedata
from collections import Counter
from importlib import resources
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from ..models import EventKind, Finding, TraceEvent, TraceState, TrustLevel
from .base import Detector


_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_TOKEN = re.compile(r"[a-z0-9_@.+$'-]+")
_SIDE_EFFECT = re.compile(
    r"\b(?:send|email|share|forward|upload|delete|remove|transfer|pay|purchase|buy|sell|withdraw|"
    r"deposit|grant|unlock|disable|change|update|schedule|dispatch|move|redirect|create|leave|"
    r"download|fill|play|book|reserve|cancel|invite|execute|run|install|reveal|disclose|access|"
    r"get|find|retrieve|retrive|search|list|check|fetch|provide|give|generate|guide|use)\b"
)
_POLICY_CHANGE = re.compile(
    r"\b(?:blacklist|blocklist|whitelist|allowlist|security\s+policy|access\s+policy|sharing\s+settings|"
    r"two-factor|2fa|permission|permanent\s+access)\b"
)
_SENSITIVE_DATA = re.compile(
    r"\b(?:password|credential|token|secret|medical|health|genetic|financial|bank|payment|account|"
    r"private|confidential|history|personal\s+details?|security\s+log)\b"
)
_META_CONTEXT = re.compile(
    r"\b(?:story|example|sentence|phrase|warning|code|documentation|explain|translate|meaning|definition|"
    r"what\s+does|how\s+do|can\s+i|should\s+i|is\s+it\s+safe)\b"
)
_INSTRUCTION_START = re.compile(
    r"\b(?:please|kindly|can\s+you|could\s+you|would\s+you|will\s+you)\b",
    re.IGNORECASE,
)
_DELIMITED_ACTION = re.compile(
    r"(?:[\n.!?;:]\s*[\"']?\s*|[\"']\s*)(send|email|share|forward|upload|delete|remove|transfer|pay|purchase|buy|sell|withdraw|"
    r"deposit|grant|unlock|disable|change|update|schedule|dispatch|move|redirect|create|leave|"
    r"download|fill|play|book|reserve|cancel|invite|execute|run|install|reveal|disclose|access|"
    r"get|find|retrieve|retrive|search|list|check|fetch|provide|give|generate|guide|use)\b",
    re.IGNORECASE,
)


def normalize_contextual_text(text: str) -> str:
    """Canonicalize low-risk obfuscations without executing or decoding content."""

    normalized = html.unescape(text or "")
    normalized = unicodedata.normalize("NFKC", normalized).lower()
    normalized = _INVISIBLE.sub("", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


def contextual_features(text: str) -> Counter[str]:
    """Sparse, deterministic features for instruction-shaped untrusted text."""

    normalized = normalize_contextual_text(text)
    words = _TOKEN.findall(normalized)
    features: Counter[str] = Counter()
    for word in set(words):
        features[f"w:{word}"] = 1
    for first, second in set(zip(words, words[1:])):
        features[f"b:{first}_{second}"] = 1
    compact = re.sub(r"\s+", " ", normalized)
    for size in (3, 4, 5):
        for index in range(max(0, len(compact) - size + 1)):
            features[f"c{size}:{compact[index:index + size]}"] = 1

    question_words = {"can", "could", "should", "what", "why", "how", "is", "are"}
    features["s:question"] = int("?" in normalized or bool(words and words[0] in question_words))
    features["s:polite_imperative"] = int(bool(re.search(r"^(?:please|kindly)\b", normalized)))
    features["s:sequence"] = int(bool(re.search(r"\b(?:then|after|once|first|finally)\b", normalized)))
    features["s:destination"] = int(
        bool(re.search(r"[\w.+-]+@[\w.-]+|https?://|account(?:\s+number|_id)?", normalized))
    )
    features["s:side_effect"] = int(bool(_SIDE_EFFECT.search(normalized)))
    features["s:policy_change"] = int(bool(_POLICY_CHANGE.search(normalized)))
    features["s:sensitive_data"] = int(bool(_SENSITIVE_DATA.search(normalized)))
    features["s:meta_context"] = int(bool(_META_CONTEXT.search(normalized)))
    return features


def is_action_candidate(text: str) -> bool:
    """Require action-bearing evidence before consulting the statistical model.

    This guard prevents topic-only prose (for example, an ordinary meeting
    announcement) from being treated as an instruction solely because of a
    distributional model score.
    """

    normalized = normalize_contextual_text(text)
    features = contextual_features(normalized)
    has_action = bool(
        features["s:side_effect"]
        or features["s:policy_change"]
        or (features["s:destination"] and features["s:sensitive_data"])
    )
    instruction_shape = bool(
        re.search(r"^(?:please|kindly)\b", normalized)
        or re.search(r"^(?:can|could|would|will)\s+you\b", normalized)
        or _SIDE_EFFECT.match(normalized)
        or re.search(r"\b(?:then|once|after|first|finally)\b.{0,100}", normalized)
    )
    return has_action and instruction_shape


def extract_text_candidates(
    value: Any,
    *,
    max_depth: int = 6,
    max_candidates: int = 128,
    max_text_length: int = 20_000,
) -> List[Tuple[str, str]]:
    """Extract bounded string leaves from nested or serialized tool output.

    JSON and Python-literal containers are parsed only as data. No arbitrary code,
    base64 payload, URL, template, or escape sequence is executed.
    """

    candidates: List[Tuple[str, str]] = []

    def add(path: str, item: Any, depth: int) -> None:
        if depth > max_depth or len(candidates) >= max_candidates:
            return
        if isinstance(item, Mapping):
            for key, child in item.items():
                add(f"{path}.{str(key)[:80]}", child, depth + 1)
            return
        if isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                add(f"{path}[{index}]", child, depth + 1)
            return
        if not isinstance(item, str):
            return

        text = item[:max_text_length]
        stripped = text.strip()
        parsed = _parse_serialized_container(stripped) if depth < max_depth else None
        if parsed is not None and parsed != item:
            add(f"{path}#decoded", parsed, depth + 1)
            return
        if stripped:
            candidates.append((path, stripped))

    add("$", value, 0)
    return candidates


def instruction_segments(text: str, *, max_segments: int = 8) -> List[str]:
    """Return the field and bounded suffixes that begin like independent instructions."""

    stripped = text.strip()
    segments = [stripped] if stripped else []
    for match in _INSTRUCTION_START.finditer(stripped):
        if match.start() == 0:
            continue
        suffix = stripped[match.start() :].strip()
        if len(suffix) >= 8 and suffix not in segments:
            segments.append(suffix)
        if len(segments) >= max_segments:
            break
    for match in _DELIMITED_ACTION.finditer(stripped):
        start = match.start(1)
        suffix = stripped[start:].strip()
        if len(suffix) >= 8 and suffix not in segments:
            segments.append(suffix)
        if len(segments) >= max_segments:
            break
    return segments


def _parse_serialized_container(text: str) -> Optional[Any]:
    if len(text) < 2 or len(text) > 20_000:
        return None
    if text[0] not in "[{\"'" or text[-1] not in "]}\"'":
        return None
    try:
        parsed = json.loads(text)
        if isinstance(parsed, (dict, list, str)):
            return parsed
    except (json.JSONDecodeError, RecursionError):
        pass
    if text[0] not in "[{('\\\"":
        return None
    try:
        parsed = ast.literal_eval(text)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return None
    return parsed if isinstance(parsed, (dict, list, tuple, str)) else None


class ContextualInjectionDetector(Detector):
    """Detect instruction-like commands embedded inside untrusted tool data.

    The bundled linear model is intentionally small and auditable. It complements,
    but never replaces, deterministic authorization and sandbox enforcement.
    """

    name = "contextual_injection_v3"

    def __init__(self, model_path: Optional[Path] = None) -> None:
        if model_path is None:
            model_resource = resources.files("agentguard").joinpath("assets/contextual_injection_v3.json")
            with model_resource.open("r", encoding="utf-8") as handle:
                model = json.load(handle)
        else:
            with Path(model_path).open(encoding="utf-8") as handle:
                model = json.load(handle)
        self.threshold = float(model["threshold"])
        self.bias = float(model["bias"])
        self.weights: Dict[str, float] = {key: float(value) for key, value in model["weights"].items()}
        self.metadata = model.get("metadata", {})

    def score_text(self, text: str) -> float:
        features = contextual_features(text)
        logit = self.bias + sum(self.weights.get(name, 0.0) * value for name, value in features.items())
        logit = max(-30.0, min(30.0, logit))
        return 1.0 / (1.0 + math.exp(-logit))

    def analyze(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        if event.kind != EventKind.TOOL_RESULT or event.trust == TrustLevel.TRUSTED:
            return []

        scored = []
        for path, text in extract_text_candidates(event.content):
            for segment_index, segment in enumerate(instruction_segments(text)):
                if len(normalize_contextual_text(segment)) < 8 or not is_action_candidate(segment):
                    continue
                segment_path = path if segment_index == 0 else f"{path}#segment[{segment_index}]"
                scored.append((self.score_text(segment), segment_path, segment))
        if not scored:
            return []
        probability, path, text = max(scored, key=lambda item: item[0])
        if probability < self.threshold:
            return []

        confidence = min(0.99, max(0.60, probability))
        return [
            Finding(
                detector=self.name,
                category="indirect_prompt_injection_contextual",
                title="Untrusted field contains an independent action request",
                description=(
                    "A calibrated instruction/data classifier found action-oriented language in an external "
                    "tool-output field. The field may be attempting to redirect the agent beyond the user's intent."
                ),
                severity=64,
                confidence=confidence,
                evidence=f"{path}: {self._clip(text)}",
                recommendation=(
                    "Quarantine this field and require an independent intent or authorization check before any "
                    "state-changing tool call."
                ),
                critical=False,
                tags=["OWASP-LLM01", "instruction-data-boundary", "statistical-detector-v3"],
            )
        ]

    @staticmethod
    def _clip(text: str, limit: int = 220) -> str:
        clean = re.sub(r"\s+", " ", text).strip()
        return clean if len(clean) <= limit else clean[: limit - 1] + "…"
