
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:5000"
MARKER = "XSS_BROWSER_TEST_MARKER"


def test_reflected_input_is_not_executed():
    payload = (
        "<img src='invalid-xss-test-image' "
        f"onerror=\"document.title='{MARKER}'\">"
    )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()

        try:
            page.goto(f"{BASE_URL}/xss-lab")

            # Select the form containing the search input.
            search_form = page.locator("form").filter(
                has=page.locator('input[name="search"]')
            )

            search_form.locator(
                'input[name="search"]'
            ).fill(payload)

            search_form.get_by_role(
                "button", name="Test Search"
            ).click()

            page.wait_for_load_state("domcontentloaded")

            # The marker should not execute in secure mode.
            assert page.title() != MARKER, (
                "FAIL: The proof-of-execution marker ran."
            )

            # Confirm the submitted HTML appears as text.
            body_text = page.locator("body").inner_text()

            assert payload in body_text, (
                "FAIL: The submitted payload was not found "
                "as visible text in the page."
            )

            assert "PASS" in body_text, (
                "FAIL: The page did not report a passing "
                "escaping verification."
            )

            print(
                "PASS: Reflected input was displayed as text "
                "and the marker did not execute."
            )

        finally:
            browser.close()


if __name__ == "__main__":
    test_reflected_input_is_not_executed()
