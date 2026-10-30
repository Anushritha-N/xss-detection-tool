
import re
from html import escape


# High-confidence patterns for this controlled demonstration.
HIGH_CONFIDENCE_PATTERNS = [
    re.compile(
        r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"<\s*script\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bon\w+\s*=\s*(['\"]).*?\1",
        re.IGNORECASE | re.DOTALL,
    ),
]

# Patterns that warrant review without meeting the block threshold.
REVIEW_PATTERNS = [
    re.compile(r"\bjavascript\s*:", re.IGNORECASE),
]


def inspect_input(value):
    """Classify input and assign a demonstration severity level."""

    if any(pattern.search(value) for pattern in HIGH_CONFIDENCE_PATTERNS):
        return {
            "action": "BLOCK",
            "severity": "HIGH",
            "reason": "High-confidence script-injection pattern detected.",
        }

    if any(pattern.search(value) for pattern in REVIEW_PATTERNS):
        return {
            "action": "FLAG",
            "severity": "MEDIUM",
            "reason": "HTML-like or script-related input requires review.",
        }

    return {
        "action": "ACCEPT",
        "severity": "LOW",
        "reason": "No configured suspicious pattern detected.",
    }


def safe_display(value):
    """Escape untrusted text before placing it in an HTML context."""
    return escape(value, quote=True)
