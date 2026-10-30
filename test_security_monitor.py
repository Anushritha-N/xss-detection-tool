
from security_monitor import inspect_input


def test_script_tag_is_blocked():
    result = inspect_input("<script>alert('test')</script>")

    assert result["action"] == "BLOCK"
    assert result["severity"] == "HIGH"


def test_script_opening_tag_is_blocked():
    result = inspect_input("<script")

    assert result["action"] == "BLOCK"
    assert result["severity"] == "HIGH"


def test_event_handler_pattern_is_blocked():
    result = inspect_input('<img onerror="test">')

    assert result["action"] == "BLOCK"
    assert result["severity"] == "HIGH"


def test_html_like_input_is_accepted():
    result = inspect_input("<b>Hello</b>")

    assert result["action"] == "ACCEPT"
    assert result["severity"] == "LOW"


def test_javascript_scheme_is_flagged():
    result = inspect_input("javascript:example")

    assert result["action"] == "FLAG"
    assert result["severity"] == "MEDIUM"


def test_plain_text_is_accepted():
    result = inspect_input("Hello, this is a normal comment.")

    assert result["action"] == "ACCEPT"
    assert result["severity"] == "LOW"


def test_lone_html_symbol_in_explanation_is_accepted():
    result = inspect_input("Use the < symbol in this explanation.")

    assert result["action"] == "ACCEPT"
    assert result["severity"] == "LOW"


def test_html_example_in_documentation_is_accepted():
    result = inspect_input("Use <b>bold</b> to emphasize a word.")

    assert result["action"] == "ACCEPT"
    assert result["severity"] == "LOW"


def test_greater_than_symbol_in_plain_text_is_accepted():
    result = inspect_input("The score is greater than 50 > 40.")

    assert result["action"] == "ACCEPT"
    assert result["severity"] == "LOW"


def test_javascript_word_without_scheme_is_accepted():
    result = inspect_input("I am learning JavaScript programming.")

    assert result["action"] == "ACCEPT"
    assert result["severity"] == "LOW"


def test_html_encoded_script_text_is_accepted():
    result = inspect_input("&lt;script&gt;alert(1)&lt;/script&gt;")

    assert result["action"] == "ACCEPT"
    assert result["severity"] == "LOW"
