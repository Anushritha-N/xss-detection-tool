
from flask import Flask, request
from html import escape

app = Flask(__name__)


@app.route("/")
def secure_reflected_test():
    user_input = request.args.get("q", "")

    # Encode untrusted input before inserting it into the HTML body.
    safe_input = escape(user_input, quote=True)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secured XSS Test Fixture</title>
</head>
<body>
    <h1>Secured Reflected XSS Test</h1>
    <p>Test output:</p>
    <div>{safe_input}</div>
</body>
</html>
"""


if __name__ == "__main__":
    # Use a separate local port for the secured fixture.
    app.run(host="127.0.0.1", port=5002, debug=False)
