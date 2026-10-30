import csv
import sqlite3
from collections import Counter
from html import escape
from pathlib import Path

from flask import Flask, session, render_template, request, redirect, url_for, send_file
from xss_fixtures import render_reflected_fixture, verify_fixture_output
from xss_checks import verify_output_is_escaped
from security_monitor import inspect_input
import os
from functools import wraps
import time

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

if not app.secret_key or not ADMIN_USERNAME or not ADMIN_PASSWORD:
    raise RuntimeError(
        "Set FLASK_SECRET_KEY, ADMIN_USERNAME, and ADMIN_PASSWORD "
        "before starting the application."
    )

# Login attempt protection
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 60
login_attempts = {}

DATABASE = Path(__file__).parent / "comments.db"
REPORT_PATH = Path(__file__).parent / "reports" / "xss_verification_report.csv"


DATABASE = Path(__file__).parent / "comments.db"
REPORT_PATH = Path(__file__).parent / "reports" / "xss_verification_report.csv"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submitted_text TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        
        # Add a source column to existing databases without losing events.
        columns = connection.execute(
            "PRAGMA table_info(security_events)"
        ).fetchall()

        if not any(column["name"] == "source" for column in columns):
            connection.execute(
                """
                ALTER TABLE security_events
                ADD COLUMN source TEXT NOT NULL DEFAULT 'manual_submission'
                """
            )
        
        # Add severity to existing databases without losing events.
        columns = connection.execute(
            "PRAGMA table_info(security_events)"
        ).fetchall()

        if not any(column["name"] == "severity" for column in columns):
            connection.execute(
                """
                ALTER TABLE security_events
                ADD COLUMN severity TEXT NOT NULL DEFAULT 'MEDIUM'
                """
            )



initialize_database()


def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view_function(*args, **kwargs)

    return wrapped_view



@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    client_key = request.remote_addr or "unknown"
    now = time.time()

    attempt = login_attempts.get(
        client_key,
        {"failures": 0, "locked_until": 0}
    )

    if now < attempt["locked_until"]:
        remaining = int(attempt["locked_until"] - now) + 1
        error = (
            f"Too many failed attempts. Try again in "
            f"{remaining} seconds."
        )

    elif request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            login_attempts.pop(client_key, None)
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("dashboard"))

        attempt["failures"] += 1

        if attempt["failures"] >= MAX_LOGIN_ATTEMPTS:
            attempt["locked_until"] = now + LOGIN_LOCKOUT_SECONDS
            attempt["failures"] = 0
            error = (
                "Too many failed attempts. Please try again in "
                f"{LOGIN_LOCKOUT_SECONDS} seconds."
            )
        else:
            error = "Invalid username or password."

        login_attempts[client_key] = attempt

    return render_template("login.html", error=error)



@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
def home():
    search_text = ""

    if request.method == "POST" and request.form.get("form_type") == "search":
        search_text = request.form.get("search", "").strip()

    with get_db_connection() as connection:
        comments = connection.execute(
            "SELECT id, content, created_at FROM comments ORDER BY id DESC"
        ).fetchall()

    stored_results = []

    for comment in comments:
        content = comment["content"]
        rendered_output = f"<p>{escape(content, quote=True)}</p>"

        result = verify_output_is_escaped(
            content,
            rendered_output
        )

        stored_results.append({
            "content": content,
            "status": result["status"],
            "message": result["message"]
        })
    
    return render_template(
        "index.html",
        search_text=search_text,
        comments=comments,
        stored_results=stored_results,
    )


@app.route("/comment", methods=["POST"])
def add_comment():
    content = request.form.get("comment", "").strip()

    if not content:
        return redirect(url_for("xss_lab"))
    
    inspection = inspect_input(content)
    action = inspection["action"]
    reason = inspection["reason"]
    severity = inspection["severity"]
    source = (
        "automated_test"
        if request.headers.get("X-Security-Test") == "automated_test"
        else "manual_submission"
    )

    # Record suspicious submissions for monitoring.
    with get_db_connection() as connection:
        if action in ("BLOCK", "FLAG"):
            connection.execute(
                """
                INSERT INTO security_events
                    (submitted_text, action, reason, source, severity)
                VALUES (?, ?, ?, ?, ?)
                """,
                (content, action, reason, source, severity),
            )

        # High-confidence suspicious input is not published.
        if (
            action == "BLOCK"
            and not app.config.get("TEST_ALLOW_SUSPICIOUS_COMMENTS", False)
        ):
            return redirect(url_for("home"))

        # Accept normal and flagged input; the template must
        # continue displaying it using Jinja's automatic escaping.
        connection.execute(
            "INSERT INTO comments (content) VALUES (?)",
            (content,),
        )

    return redirect(url_for("home"))


@app.route("/delete-comment/<int:comment_id>", methods=["POST"])
def delete_comment(comment_id):
    with get_db_connection() as connection:
        connection.execute(
            "DELETE FROM comments WHERE id = ?",
            (comment_id,),
        )

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"success": True}, 200

    return redirect(url_for("home"))




@app.route("/xss-lab", methods=["GET", "POST"])
def xss_lab():
    mode = request.values.get("mode", "secure")

    if mode not in ("secure", "simulation"):
        mode = "secure"

    search_text = ""
    test_result = None

    if request.method == "POST":
        search_text = request.form.get("search", "")

        if mode == "simulation":
            simulated_output = render_reflected_fixture(
                search_text,
                vulnerable=True
            )

            verification = verify_fixture_output(
                search_text,
                simulated_output,
                context="reflected"
            )

            test_result = {
                "status": "SIMULATION ONLY",
                "verification_status": verification["status"],
                "message": (
                    "The controlled fixture generated unescaped HTML-like "
                    "output. This demonstrates a potential XSS risk if such "
                    "output were inserted into a browser page without proper "
                    "escaping. No vulnerability was executed or confirmed "
                    "in the live application."
                ),
                "verification_message": verification["message"],
                "output": simulated_output
            }

        else:
            safe_output = (
                f"<div>{escape(search_text, quote=True)}</div>"
            )

            test_result = verify_output_is_escaped(
                search_text,
                safe_output
            )

    with get_db_connection() as connection:
        comments = connection.execute(
            """
            SELECT id, content, created_at
            FROM comments
            ORDER BY id DESC
            """
        ).fetchall()

    stored_results = []

    for comment in comments:
        content = comment["content"]
        rendered_output = f"<p>{escape(content, quote=True)}</p>"

        result = verify_output_is_escaped(
            content,
            rendered_output
        )

        stored_results.append({
            "content": content,
            "status": result["status"],
            "message": result["message"]
        })

    return render_template(
        "xss_lab.html",
        mode=mode,
        search_text=search_text,
        comments=comments,
        test_result=test_result,
        stored_results=stored_results
    )




@app.route("/report")
def verification_report():
    tests = []
    category_counts = Counter()
    remediation_summary = []

    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "status": "NOT GENERATED"
    }

    generated_at = "Not available"
    browser_findings = []

    if REPORT_PATH.exists():
        with REPORT_PATH.open("r", newline="", encoding="utf-8") as file:
            rows = list(csv.reader(file))

        in_remediation_summary = False
        skip_remediation_header = False

        for row in rows[1:]:
            if not row:
                continue

            # The CSV has a separate remediation-summary section after totals.
            if row[0] == "REMEDIATION SUMMARY":
                in_remediation_summary = True
                skip_remediation_header = True
                continue

            if in_remediation_summary:
                if skip_remediation_header:
                    skip_remediation_header = False
                    continue

                if len(row) >= 3:
                    remediation_summary.append({
                        "check": row[0],
                        "result": row[1],
                        "details": row[2]
                    })
                continue

            # Read the overall report totals.
            if len(row) >= 2:
                if row[0] == "Total Tests":
                    summary["total"] = int(row[1])
                    continue
                elif row[0] == "Passed":
                    summary["passed"] = int(row[1])
                    continue
                elif row[0] == "Failed":
                    summary["failed"] = int(row[1])
                    continue
                elif row[0] == "Overall Status":
                    summary["status"] = row[1]
                    continue

            # CSV columns:
            # Generated At, Test Name, Category, Expected Behavior,
            # Test Result, Security Outcome, Remediation Status, Evidence / Details
            if len(row) >= 8 and row[0] and row[1]:
                evidence = (row[7] or "").strip()
                if not evidence:
                    # Passing pytest cases often have no captured stdout.
                    # Use the assertion-oriented remediation description as
                    # transparent supporting context rather than showing a blank cell.
                    evidence = ("Assertion summary: " + (row[6] or row[3])).strip()

                test = {
                    "name": row[1],
                    "category": row[2],
                    "expected_behavior": row[3],
                    "result": row[4],
                    "security_outcome": row[5],
                    "remediation_status": row[6],
                    "evidence": evidence
                }

                tests.append(test)
                category_counts[test["category"]] += 1
                generated_at = row[0]

    # Derive security findings from actual browser-test report rows.
    finding_definitions = [
        {
            "test_name": "Reflected XSS Browser Test",
            "title": "Reflected XSS — Secure Application",
            "recommendation": (
                "Use context-aware output encoding and avoid inserting "
                "untrusted input into HTML as raw markup."
            ),
            "evidence_label": "Browser verification"
        },
        {
            "test_name": "Stored XSS Browser Test",
            "title": "Stored XSS — Secure Application",
            "recommendation": (
                "Keep output encoding in place when displaying saved "
                "user content. Database storage alone does not prevent XSS."
            ),
            "evidence_label": "Browser verification"
        },
        {
            "test_name": "Vulnerable Fixture Browser Test",
            "title": "Reflected XSS — Isolated Vulnerable Fixture",
            "recommendation": (
                "Encode untrusted output appropriately and retest the "
                "same input in the secured version."
            ),
            "evidence_label": "Detection test"
        },
        {
            "test_name": "Vulnerable Fixture Remediation Test",
            "title": "XSS — Vulnerable Fixture Before Remediation",
            "recommendation": (
                "The test confirmed that the deliberately vulnerable fixture "
                "executes the test marker. Keep this fixture isolated and "
                "never deploy it as a production application."
            ),
            "evidence_label": "Before remediation"
        },
        {
            "test_name": "Secured Fixture Remediation Test",
            "title": "XSS — Secured Fixture After Remediation",
            "recommendation": (
                "The test should confirm that the secured fixture displays "
                "the input as text without executing the test marker."
            ),
            "evidence_label": "After remediation"
        }
    ]

    tests_by_name = {test["name"]: test for test in tests}

    for definition in finding_definitions:
        test = tests_by_name.get(definition["test_name"])

        if test is None:
            status = "NOT RUN"
            details = "No corresponding browser-test result was found."
        else:
            status = test["result"]
            details = test["evidence"] or (
                "The browser test completed without additional details."
            )

        browser_findings.append({
            **definition,
            "status": status,
            "details": details
        })

    return render_template(
        "report.html",
        tests=tests,
        summary=summary,
        generated_at=generated_at,
        category_counts=category_counts,
        browser_findings=browser_findings,
        remediation_summary=remediation_summary
    )

def read_security_outcomes():
    outcomes = Counter()

    if not REPORT_PATH.exists():
        return outcomes

    with REPORT_PATH.open(
        "r", newline="", encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            outcome = (row.get("Security Outcome") or "").strip()
            if outcome:
                outcomes[outcome] += 1

    return outcomes

@app.route("/dashboard")
@login_required
def dashboard():
    summary, recent_results, category_counts = read_dashboard_report()
    security_summary, security_events = read_security_events()
    security_outcomes = read_security_outcomes()

    return render_template(
        "dashboard.html",
        summary=summary,
        recent_results=recent_results,
        category_counts=category_counts,
        security_summary=security_summary,
        security_events=security_events,
        security_outcomes=security_outcomes,
        run_status=None,
        run_message=None,
        run_output="",
    )

def read_security_events():
    """Retrieve recent security events and their counts."""
    with get_db_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

        blocked = connection.execute(
            "SELECT COUNT(*) FROM security_events WHERE action = 'BLOCK'"
        ).fetchone()[0]

        flagged = connection.execute(
            "SELECT COUNT(*) FROM security_events WHERE action = 'FLAG'"
        ).fetchone()[0]

        events = connection.execute(
            """
            SELECT id, submitted_text, action, reason, created_at, source, severity
            FROM security_events
            ORDER BY id DESC
            LIMIT 20
            """
        ).fetchall()

    return {
        "total": total,
        "blocked": blocked,
        "flagged": flagged,
    }, events



@app.route("/delete-security-event/<int:event_id>", methods=["POST"])
@login_required
def delete_security_event(event_id):
    with get_db_connection() as connection:
        connection.execute(
            "DELETE FROM security_events WHERE id = ?",
            (event_id,),
        )

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"success": True}, 200

    return redirect(url_for("dashboard"))



def read_dashboard_report():
    report_path = (
        Path(__file__).parent
        / "reports"
        / "xss_verification_report.csv"
    )

    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "status": "NOT RUN",
    }
    recent_results = []
    category_counts = {}

    if not report_path.exists():
        return summary, recent_results, category_counts

    with report_path.open("r", newline="", encoding="utf-8") as file:
        rows = list(csv.reader(file))

    for row in rows:
        if len(row) >= 2:
            if row[0] == "Total Tests":
                summary["total"] = int(row[1])
            elif row[0] == "Passed":
                summary["passed"] = int(row[1])
            elif row[0] == "Failed":
                summary["failed"] = int(row[1])
            elif row[0] == "Overall Status":
                summary["status"] = row[1]

    for row in rows:
        if (
            len(row) >= 5
            and row[0] != "Generated At"
            and row[1] not in {
                "Total Tests",
                "Passed",
                "Failed",
                "Overall Status",
                "Test Name",
            }
            and row[1]
        ):
            category = row[2]
            result = row[3].upper()

            # Count each test by its report category.
            if category:
                if category not in category_counts:
                    category_counts[category] = {
                        "total": 0,
                        "passed": 0,
                        "failed": 0,
                    }

                category_counts[category]["total"] += 1

                if result in ("PASS", "PASSED"):
                    category_counts[category]["passed"] += 1
                elif result in ("FAIL", "FAILED"):
                    category_counts[category]["failed"] += 1

            recent_results.append({
                "name": row[1],
                "category": category,
                "result": row[3],
                "details": row[4],
            })

    return summary, recent_results[-8:], category_counts


def read_dashboard_summary():
    summary, _, _ = read_dashboard_report()
    return summary

def read_recent_results():
    _, results, _ = read_dashboard_report()
    return results

@app.route("/run-security-tests", methods=["POST"])
@login_required
def run_security_tests():
    import subprocess
    import sys

    project_dir = Path(__file__).parent
    generator = project_dir / "generate_report.py"

    try:
        result = subprocess.run(
            [sys.executable, str(generator)],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=180,
        )

        output = (result.stdout or "") + "\n" + (result.stderr or "")

        if result.returncode == 0:
            status = "PASS"
            message = "Security tests completed successfully."
        else:
            status = "FAIL"
            message = "Some security tests failed. Review the output below."

    except subprocess.TimeoutExpired:
        status = "FAIL"
        message = "The test run timed out after 180 seconds."
        output = ""

    except OSError as error:
        status = "FAIL"
        message = f"Could not start the test runner: {error}"
        output = ""

    
    security_summary, security_events = read_security_events()

    return render_template(
        "dashboard.html",
        summary=read_dashboard_summary(),
        recent_results=read_recent_results(),
        run_status=status,
        run_message=message,
        run_output=output[-12000:],
        category_counts=read_dashboard_report()[2],
        security_summary=security_summary,
        security_events=security_events,
    )


@app.route("/download-report")
def download_report():
    report_path = (
        Path(__file__).parent
        / "reports"
        / "xss_verification_report.csv"
    )

    if not report_path.exists():
        return (
            "No report is available yet. Run the security tests first.",
            404,
        )

    return send_file(
        report_path,
        as_attachment=True,
        download_name="xss_verification_report.csv",
        mimetype="text/csv",
    )


if __name__ == "__main__":
    app.run(debug=True)