
from html import escape


def render_reflected_fixture(user_input, vulnerable=False):
    """Simulate reflected input handling for controlled tests."""
    if vulnerable:
        # Simulated unsafe insertion into an HTML body.
        return f"<div>{user_input}</div>"

    return f"<div>{escape(user_input, quote=True)}</div>"


def render_stored_fixture(comment, vulnerable=False):
    """Simulate stored comment rendering for controlled tests."""
    if vulnerable:
        # Simulated unsafe insertion of a saved comment into HTML.
        return f"<article>{comment}</article>"

    return f"<article>{escape(comment, quote=True)}</article>"


def verify_fixture_output(payload, rendered_output, context="reflected"):
    """
    Compare fixture output against the expected safe representation.

    This verifies controlled fixture strings only. It is not a browser-based
    XSS scanner and does not prove a live application is vulnerable.
    """
    if not payload:
        return {
            "status": "INCONCLUSIVE",
            "message": "Empty input cannot be verified."
        }

    if context == "reflected":
        safe_output = render_reflected_fixture(payload, vulnerable=False)
    elif context == "stored":
        safe_output = render_stored_fixture(payload, vulnerable=False)
    else:
        return {
            "status": "INCONCLUSIVE",
            "message": "Unsupported fixture context."
        }

    if rendered_output == safe_output:
        return {
            "status": "SAFE",
            "message": "Fixture output matches the expected escaped output."
        }

    if payload in rendered_output:
        return {
            "status": "POTENTIAL RISK",
            "message": (
                "Fixture output contains the original input. "
                "This indicates a potential risk in the simulated output."
            )
        }

    return {
        "status": "INCONCLUSIVE",
        "message": (
            "Fixture output does not match the expected safe output, "
            "and the original input was not found as a complete string."
        )
    }
