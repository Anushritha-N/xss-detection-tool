
from urllib.parse import quote

from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:5001"
MARKER = "XSS_FIXTURE_EXECUTED"


def test_isolated_fixture_detects_reflected_execution():
    payload = (
        "<img src=x "
        f"onerror=\"document.title='{MARKER}'\">"
    )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()

        try:
            page.goto(f"{BASE_URL}/?q={quote(payload)}")

            # Wait briefly for the harmless image-error handler.
            page.wait_for_function(
                "() => document.title === 'XSS_FIXTURE_EXECUTED'",
                timeout=3000,
            )

            assert page.title() == MARKER

            print(
                "PASS: Browser detected script execution "
                "in the isolated vulnerable fixture."
            )

        finally:
            browser.close()


if __name__ == "__main__":
    test_isolated_fixture_detects_reflected_execution()
