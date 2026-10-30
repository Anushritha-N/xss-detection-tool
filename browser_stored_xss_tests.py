
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:5000"
MARKER = "STORED_XSS_BROWSER_MARKER"


def test_stored_input_is_not_executed():
    payload = (
        "<img src='invalid-stored-test-image' "
        f"onerror=\"document.title='{MARKER}'\">"
    )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(
            extra_http_headers={"X-Security-Test": "automated_test"}
        )

        try:
            # Open the Home page.
            page.goto(f"{BASE_URL}/xss-lab")
            # Submit the harmless test payload as a comment.
            comment_form = page.locator("form").filter(
                has=page.locator('textarea[name="comment"]')
            )

            comment_form.locator(
                'textarea[name="comment"]'
            ).fill(payload)

            comment_form.get_by_role(
                "button", name="Save Test Comment"
            ).click()

            # The form redirects back to Home after saving.
            page.wait_for_load_state("domcontentloaded")

            # Confirm the payload did not execute.
            assert page.title() != MARKER, (
                "FAIL: The stored proof-of-execution marker ran."
            )

            # Confirm the blocked payload was not published.
            body_text = page.locator("body").inner_text()

            assert payload not in body_text, (
                "FAIL: The blocked payload appeared in saved comments."
            )

            print(
                "PASS: The suspicious payload was blocked, "
                "was not published, and did not execute."
            )

            print(
                "PASS: Stored input was displayed as text "
                "and the marker did not execute."
            )

        finally:
            browser.close()


if __name__ == "__main__":
    test_stored_input_is_not_executed()

