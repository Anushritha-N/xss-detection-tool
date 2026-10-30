
from urllib.parse import quote

from playwright.sync_api import sync_playwright

VULNERABLE_URL = "http://127.0.0.1:5001"
SECURE_URL = "http://127.0.0.1:5002"

MARKER = "XSS_REMEDIATION_MARKER"

PAYLOAD = (
    "<img src='invalid-remediation-test-image' "
    f"onerror=\"document.title='{MARKER}'\">"
)


def test_vulnerable_fixture_executes_marker():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()

        try:
            page.goto(
                f"{VULNERABLE_URL}/?q={quote(PAYLOAD)}"
            )

            page.wait_for_function(
                "() => document.title === 'XSS_REMEDIATION_MARKER'",
                timeout=3000,
            )

            assert page.title() == MARKER

            print(
                "PASS: Vulnerable fixture executed the test marker."
            )
        finally:
            browser.close()


def test_secure_fixture_prevents_marker_execution():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()

        try:
            page.goto(
                f"{SECURE_URL}/?q={quote(PAYLOAD)}"
            )

            # Wait for the document to load before checking its state.
            page.wait_for_load_state("domcontentloaded")

            assert page.title() != MARKER, (
                "FAIL: Marker executed in the secured fixture."
            )

            # Confirm the input is visible as text.
            assert PAYLOAD in page.locator("body").inner_text(), (
                "FAIL: The original input was not displayed as text."
            )

            print(
                "PASS: Secured fixture displayed the input as text "
                "without executing the marker."
            )
        finally:
            browser.close()


if __name__ == "__main__":
    test_vulnerable_fixture_executes_marker()
    test_secure_fixture_prevents_marker_execution()
