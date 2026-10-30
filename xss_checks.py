
from html import escape


def verify_output_is_escaped(payload, rendered_html):
    """
    Basic output-escaping verification for controlled tests.
    This is a heuristic, not a complete XSS scanner.
    """
    if not payload:
        return {
            "status": "INCONCLUSIVE",
            "message": "Empty input cannot be verified by this check."
        }

    escaped_payload = escape(payload, quote=True)

    if escaped_payload == payload:
        return {
            "status": "INCONCLUSIVE",
            "message": (
                "Input contains no characters changed by HTML escaping; "
                "use a test marker containing HTML-sensitive characters."
            )
        }

    # Check for the original input first. If it appears anywhere in
    # the rendered output, do not report PASS just because an escaped
    # copy also exists.
    if payload in rendered_html:
        return {
            "status": "FAIL",
            "message": (
                "The original unescaped input was found in the rendered "
                "output. The output-escaping check failed."
            )
        }

    if escaped_payload in rendered_html:
        return {
            "status": "PASS",
            "message": (
                "Expected HTML-escaped input was found, and the original "
                "unescaped input was not found in the rendered output."
            )
        }

    return {
        "status": "INCONCLUSIVE",
        "message": (
            "Neither the expected escaped input nor the original input "
            "was found in the rendered output."
        )
    }
