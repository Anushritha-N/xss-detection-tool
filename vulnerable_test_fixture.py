
from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def vulnerable_reflected_test():
    user_input = request.args.get("q", "")

    # Deliberately unsafe HTML insertion for local testing only.
    # Never use this pattern in a real application.
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Isolated XSS Test Fixture</title>
    </head>
    <body>
        <h1>Isolated Reflected XSS Test</h1>
        <p>Test output:</p>
        <div>{user_input}</div>
    </body>
    </html>
    """


if __name__ == "__main__":
    # Separate port so this fixture doesn't replace your main app.
    app.run(host="127.0.0.1", port=5001, debug=False)
