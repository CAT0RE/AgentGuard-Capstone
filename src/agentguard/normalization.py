from __future__ import annotations

import html
import re
import unicodedata


_FORMAT_CONTROLS = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_WHITESPACE = re.compile(r"\s+")


def normalize_security_text(value: str) -> str:
    """Canonicalize text before matching security signatures.

    The transformation is deliberately bounded and deterministic: it decodes
    HTML entities, applies Unicode compatibility normalization, removes common
    invisible formatting controls, and collapses whitespace. It does not execute
    or recursively decode attacker-controlled payloads.
    """

    text = html.unescape(value or "")
    text = unicodedata.normalize("NFKC", text)
    text = _FORMAT_CONTROLS.sub("", text)
    return _WHITESPACE.sub(" ", text).strip()
