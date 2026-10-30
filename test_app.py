
import pytest
import app as application



@pytest.fixture
def client(tmp_path, monkeypatch):
    test_database = tmp_path / "test_comments.db"

    monkeypatch.setattr(
        application, "DATABASE", test_database
    )
    application.initialize_database()

    application.app.config["TESTING"] = True
    application.app.config["TEST_ALLOW_SUSPICIOUS_COMMENTS"] = True

    with application.app.test_client() as client:
        yield client

    application.app.config.pop(
        "TEST_ALLOW_SUSPICIOUS_COMMENTS", None
    )


def test_reflected_input_is_escaped(client):
    payload = "<script>testMarker()</script>"

    response = client.post(
        "/xss-lab",
        data={"mode": "secure", "search": payload},
    )

    assert response.status_code == 200
    assert b"&lt;script&gt;" in response.data
    assert b"<script>testMarker()</script>" not in response.data


def test_stored_comment_is_escaped(client):
    payload = "<script>testMarker()</script>"

    response = client.post(
        "/comment",
        data={"comment": payload},
    )
    response = client.get("/xss-lab")

    assert response.status_code == 200
    assert b"&lt;script&gt;" in response.data
    assert b"<script>testMarker()</script>" not in response.data



def test_stored_comment_remains_escaped_after_retrieval(client):
    payload = '<b>STORED_XSS_MARKER</b> "quoted"'

    response = client.post(
        "/comment",
        data={"comment": payload},
    )
    response = client.get("/xss-lab")

    assert response.status_code == 200

    # Verify HTML-sensitive characters are escaped in the response.
    assert b"&lt;b&gt;STORED_XSS_MARKER&lt;/b&gt;" in response.data
    assert b"&#34;quoted&#34;" in response.data

    # Ensure the original HTML markup is not rendered in the response.
    assert b"<b>STORED_XSS_MARKER</b>" not in response.data


def test_multiple_stored_comments_are_displayed_safely(client):
    first_comment = "<b>FIRST_MARKER</b>"
    second_comment = '<i>SECOND_MARKER</i> "quoted"'

    client.post("/comment", data={"comment": first_comment})
    client.post("/comment", data={"comment": second_comment})

    response = client.get("/xss-lab")

    assert response.status_code == 200

    # Both comments should be displayed in escaped form.
    assert b"&lt;b&gt;FIRST_MARKER&lt;/b&gt;" in response.data
    assert b"&lt;i&gt;SECOND_MARKER&lt;/i&gt;" in response.data
    assert b"FIRST_MARKER" in response.data
    assert b"SECOND_MARKER" in response.data

    # Neither original HTML tag should be rendered as markup.
    assert b"<b>FIRST_MARKER</b>" not in response.data
    assert b"<i>SECOND_MARKER</i>" not in response.data



def test_reflected_html_attribute_input_is_escaped(client):
    payload = '<img src="invalid" onerror="XSS_TEST_MARKER">'

    response = client.post(
        "/xss-lab",
        data={"mode": "secure", "search": payload}
    )

    assert response.status_code == 200

    # Verify the HTML element is escaped in the response.
    assert b"&lt;img" in response.data
    assert b"&gt;" in response.data
    assert b"onerror" in response.data

    # Ensure the submitted element does not appear as raw HTML.
    assert payload.encode() not in response.data
    assert b"<img src=" not in response.data


def test_stored_html_attribute_input_is_escaped(client):
    payload = '<img src="invalid" onerror="STORED_MARKER">'

    response = client.post(
        "/comment",
        data={"comment": payload},
    )
    response = client.get("/xss-lab")

    assert response.status_code == 200
    assert b"&lt;img" in response.data
    assert b"onerror" in response.data
    assert payload.encode() not in response.data
    assert b"<img src=" not in response.data


def test_reflected_special_characters_are_escaped(client):
    payload = '<tag> "quoted" & \'single\''

    response = client.post(
        "/xss-lab",
        data={"mode": "secure", "search": payload}
    )

    assert response.status_code == 200

    # Verify the HTML-sensitive characters are escaped.
    assert b"&lt;tag&gt;" in response.data
    assert b"&amp;" in response.data
    assert b"&#34;" in response.data
    assert b"&#39;" in response.data

    # The original unescaped input must not appear in the response.
    assert payload.encode() not in response.data


def test_stored_comment_remains_escaped_across_page_requests(client):
    payload = '<b>PERSISTENCE_MARKER</b> "quoted"'

    # Save the comment.
    save_response = client.post(
        "/comment",
        data={"comment": payload},
        follow_redirects=True
    )
    assert save_response.status_code == 200

    # Retrieve the page again in a separate request.
    first_response = client.get("/xss-lab")
    second_response = client.get("/xss-lab")

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    escaped_marker = b"&lt;b&gt;PERSISTENCE_MARKER&lt;/b&gt;"
    assert escaped_marker in first_response.data
    assert escaped_marker in second_response.data

    # The raw HTML must never appear in either response.
    assert b"<b>PERSISTENCE_MARKER</b>" not in first_response.data
    assert b"<b>PERSISTENCE_MARKER</b>" not in second_response.data


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_delete_security_event_requires_login(client):
    response = client.post("/delete-security-event/1")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_run_security_tests_requires_login(client):
    response = client.post("/run-security-tests")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
