
import pytest

from security_monitor import inspect_input


@pytest.mark.parametrize(
    ("category", "payload", "expected_action"),
    [
        (
            "script tag",
            "<script>alert('test')</script>",
            "BLOCK",
        ),
        (
            "event handler",
            '<img onerror="test">',
            "BLOCK",
        ),
        (
            "ordinary HTML",
            "<b>Hello</b>",
            "ACCEPT",
        ),
        (
            "JavaScript scheme",
            "javascript:example",
            "FLAG",
        ),
        (
            "plain text",
            "Hello, this is a normal comment.",
            "ACCEPT",
        ),
        (
            "HTML documentation",
            "Use <b>bold</b> to emphasize a word.",
            "ACCEPT",
        ),
        (
            "JavaScript mentioned in text",
            "I am learning JavaScript programming.",
            "ACCEPT",
        ),
        (
            "HTML-encoded script text",
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "ACCEPT",
        ),
        (
            "greater-than symbol",
            "The score is greater than 50 > 40.",
            "ACCEPT",
        ),
    ],
)
def test_detection_matrix(category, payload, expected_action):
    result = inspect_input(payload)

    assert result["action"] == expected_action, (
        f"Category: {category}; "
        f"expected {expected_action}, got {result['action']}"
    )
