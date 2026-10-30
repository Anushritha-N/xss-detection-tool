
from xss_fixtures import (
    render_reflected_fixture,
    render_stored_fixture,
)


def test_reflected_fixture_distinguishes_unsafe_and_safe_output():
    marker = "<b>XSS_TEST_MARKER</b>"

    unsafe_html = render_reflected_fixture(marker, vulnerable=True)
    safe_html = render_reflected_fixture(marker, vulnerable=False)

    assert "<b>XSS_TEST_MARKER</b>" in unsafe_html
    assert "&lt;b&gt;XSS_TEST_MARKER&lt;/b&gt;" in safe_html


def test_stored_fixture_distinguishes_unsafe_and_safe_output():
    marker = "<b>XSS_TEST_MARKER</b>"

    unsafe_html = render_stored_fixture(marker, vulnerable=True)
    safe_html = render_stored_fixture(marker, vulnerable=False)

    assert "<b>XSS_TEST_MARKER</b>" in unsafe_html
    assert "&lt;b&gt;XSS_TEST_MARKER&lt;/b&gt;" in safe_html


from xss_fixtures import verify_fixture_output


def test_reflected_fixture_verification_detects_potential_risk():
    payload = "<b>FIXTURE_MARKER</b>"
    output = render_reflected_fixture(payload, vulnerable=True)

    result = verify_fixture_output(payload, output, context="reflected")

    assert result["status"] == "POTENTIAL RISK"


def test_stored_fixture_verification_accepts_safe_output():
    payload = "<b>FIXTURE_MARKER</b>"
    output = render_stored_fixture(payload, vulnerable=False)

    result = verify_fixture_output(payload, output, context="stored")

    assert result["status"] == "SAFE"
