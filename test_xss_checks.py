
from xss_checks import verify_output_is_escaped


def test_escaped_html_is_recognized():
    payload = "<b>XSS_TEST_MARKER</b>"
    rendered_html = "&lt;b&gt;XSS_TEST_MARKER&lt;/b&gt;"

    result = verify_output_is_escaped(payload, rendered_html)

    assert result["status"] == "PASS"


def test_unescaped_html_is_rejected():
    payload = "<b>XSS_TEST_MARKER</b>"
    rendered_html = "<div><b>XSS_TEST_MARKER</b></div>"

    result = verify_output_is_escaped(payload, rendered_html)

    assert result["status"] == "FAIL"


def test_empty_input_is_inconclusive():
    result = verify_output_is_escaped("", "<div></div>")

    assert result["status"] == "INCONCLUSIVE"


def test_plain_text_without_html_sensitive_characters_is_inconclusive():
    result = verify_output_is_escaped(
        "Hello XSS Test",
        "<div>Hello XSS Test</div>"
    )

    assert result["status"] == "INCONCLUSIVE"


def test_missing_input_is_inconclusive():
    result = verify_output_is_escaped(
        "<b>XSS_TEST_MARKER</b>",
        "<div>Different content</div>"
    )

    assert result["status"] == "INCONCLUSIVE"


def test_unescaped_input_is_rejected_even_if_escaped_copy_exists():
    payload = "<b>XSS_TEST_MARKER</b>"
    rendered_html = (
        "<div>&lt;b&gt;XSS_TEST_MARKER&lt;/b&gt;</div>"
        "<div><b>XSS_TEST_MARKER</b></div>"
    )

    result = verify_output_is_escaped(payload, rendered_html)

    assert result["status"] == "FAIL"
