
import csv
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_DIR = Path(__file__).parent
REPORT_DIR = PROJECT_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

report_json = REPORT_DIR / "pytest_results.json"
report_csv = REPORT_DIR / "xss_verification_report.csv"
generated_at = datetime.now().isoformat(timespec="seconds")
errors = []
report_rows = []

pytest_files = [
    "test_app.py",
    "test_xss_checks.py",
    "test_xss_fixtures.py",
]

browser_tests = [
    {
        "file": "browser_xss_tests.py",
        "name": "Reflected XSS Browser Test",
        "category": "Reflected XSS Browser Verification",
    },
    {
        "file": "browser_stored_xss_tests.py",
        "name": "Stored XSS Browser Test",
        "category": "Stored XSS Browser Verification",
    },
    {
        "file": "test_vulnerable_fixture.py",
        "name": "Vulnerable Fixture Browser Test",
        "category": "Vulnerable Fixture Detection",
    },
    {
        "file": "test_remediation.py",
        "name": "Vulnerable Fixture Remediation Test",
        "category": "Vulnerable Fixture Detection",
        "scenario": "vulnerable",
    },
    {
        "file": "test_remediation.py",
        "name": "Secured Fixture Remediation Test",
        "category": "Remediation Verification",
        "scenario": "secured",
    },
]


def categorize_test(test_name):
    """Assign a report category based on the test's purpose."""
    name = test_name.lower()

    if "fixture" in name or "simulation" in name:
        return "Controlled Simulation"

    if "stored" in name or "multiple_stored" in name:
        return "Stored XSS Verification"

    if "reflected" in name:
        return "Reflected XSS Verification"

    if "unescaped" in name:
        return "Escaping Regression Test"

    if "inconclusive" in name or "missing_input" in name:
        return "Input Handling"

    if "escaped_html" in name:
        return "Escaping Verification"

    return "General Regression Test"


def run_remediation_scenario(scenario):
    """Run one specific remediation test without running the other."""
    if scenario == "vulnerable":
        function_name = "test_vulnerable_fixture_executes_marker"
    elif scenario == "secured":
        function_name = "test_secure_fixture_prevents_marker_execution"
    else:
        raise ValueError(f"Unknown remediation scenario: {scenario}")

    command = [
        sys.executable,
        "-c",
        (
            "import test_remediation; "
            f"test_remediation.{function_name}()"
        ),
    ]

    return subprocess.run(
        command,
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
        timeout=60,
    )

def get_security_outcome(name, outcome, details):
    if outcome != "PASS":
        return "Needs Investigation"

    name_lower = name.lower()
    details_lower = details.lower()

    if "vulnerable fixture browser test" in name_lower:
        return "Vulnerability Detected"

    if "vulnerable fixture remediation test" in name_lower:
        return "Vulnerable Behavior Verified"

    if "secured fixture remediation test" in name_lower:
        return "Mitigation Verified"

    if "reflected xss browser test" in name_lower:
        return "Reflected XSS Mitigation Verified"

    if "stored xss browser test" in name_lower:
        return "Stored XSS Mitigation Verified"

    if "test_unescaped" in name_lower:
        return "Unsafe Output Detection Verified"

    if "test_escaped" in name_lower:
        return "Safe Output Verification Passed"

    if "test_multiple_stored_comments_are_displayed_safely" in name_lower:
        return "Mitigation Verified"

    if "test_reflected_fixture_distinguishes_unsafe_and_safe_output" in name_lower:
        return "Unsafe and Safe Output Differentiation Verified"

    if "test_stored_fixture_distinguishes_unsafe_and_safe_output" in name_lower:
        return "Unsafe and Safe Output Differentiation Verified"

    if "test_reflected_fixture_verification_detects_potential_risk" in name_lower:
        return "Potential XSS Risk Detection Verified"

    if "test_stored_fixture_verification_accepts_safe_output" in name_lower:
        return "Safe Output Verification Passed"

    if "test_reflected" in name_lower or "test_stored" in name_lower:
        return "Mitigation Verified"

    if "secured fixture" in details_lower:
        return "Mitigation Verified"

    if "vulnerable fixture" in details_lower:
        return "Vulnerable Behavior Verified"

    return "Security Check Passed"



def get_expected_behavior(name):
    """Describe the intended behavior for known test cases."""
    name_lower = name.lower()

    if "test_unescaped_html_is_rejected" in name_lower:
        return "Unescaped HTML should be rejected as unsafe output"

    if "test_escaped_html_is_recognized" in name_lower:
        return "Escaped HTML should be recognized as safe output"

    if "test_unescaped_input_is_rejected_even_if_escaped_copy_exists" in name_lower:
        return "Unsafe input should not be accepted merely because an escaped copy exists"

    if "test_reflected_input_is_escaped" in name_lower:
        return "Reflected input should be HTML-escaped before rendering"

    if "test_stored_comment" in name_lower or "test_multiple_stored_comments" in name_lower:
        return "Stored comments should remain safely escaped when displayed"

    if "test_reflected_html_attribute_input_is_escaped" in name_lower:
        return "Reflected input in an HTML attribute context should be handled safely"

    if "test_stored_html_attribute_input_is_escaped" in name_lower:
        return "Stored input in an HTML attribute context should be handled safely"

    if "test_reflected_special_characters_are_escaped" in name_lower:
        return "Special characters in reflected input should be safely escaped"

    if "test_empty_input_is_inconclusive" in name_lower:
        return "Empty input should produce an inconclusive result"

    if "test_missing_input_is_inconclusive" in name_lower:
        return "Missing input should produce an inconclusive result"

    if "test_plain_text_without_html_sensitive_characters_is_inconclusive" in name_lower:
        return "Plain text without HTML-sensitive characters should be treated as inconclusive"

    if "vulnerable fixture" in name_lower:
        return "Controlled vulnerable fixture should demonstrate unsafe behavior"

    if "secured fixture" in name_lower:
        return "Input should be displayed safely without marker execution"

    if "reflected xss" in name_lower or "reflected" in name_lower:
        return "Reflected input should be handled safely"

    if "stored xss" in name_lower or "stored" in name_lower:
        return "Stored input should be handled safely"

    return "Review the test definition to determine its expected behavior"

def get_remediation_status(name, outcome):
    """Describe what a passing test actually establishes."""
    name_lower = name.lower()

    if outcome != "PASS":
        return "Failed - investigate test output"

    if "vulnerable fixture browser test" in name_lower:
        return "Detection verified; fixture intentionally remains vulnerable"

    if "vulnerable fixture remediation test" in name_lower:
        return "Baseline vulnerability confirmed; no remediation claimed"

    if "secured fixture remediation test" in name_lower:
        return "Mitigation verified by controlled browser test"

    if "reflected xss browser test" in name_lower:
        return "Reflected input handling verified by browser test"

    if "stored xss browser test" in name_lower:
        return "Stored input handling verified by browser test"

    
    if "test_escaped_html_is_recognized" in name_lower:
        return (
            "PASS: Escaped HTML was recognized as safe output "
            "by verify_output_is_escaped"
        )

    if "test_unescaped_html_is_rejected" in name_lower:
        return (
            "PASS: Unescaped HTML was correctly classified as FAIL "
            "by verify_output_is_escaped"
        )

    if "test_unescaped_input_is_rejected_even_if_escaped_copy_exists" in name_lower:
        return (
            "PASS: Mixed escaped and unescaped output was correctly "
            "classified as FAIL"
        )

    if "test_empty_input_is_inconclusive" in name_lower:
        return "PASS: Empty input was classified as INCONCLUSIVE"

    if "test_plain_text_without_html_sensitive_characters_is_inconclusive" in name_lower:
        return "PASS: Plain text was classified as INCONCLUSIVE"

    if "test_missing_input_is_inconclusive" in name_lower:
        return "PASS: Non-matching rendered content was classified as INCONCLUSIVE"


    if "test_escaped_html_is_recognized" in name_lower:
        return "Safe output recognition check passed"

    if "test_unescaped_input_is_rejected_even_if_escaped_copy_exists" in name_lower:
        return "Unsafe input rejection regression check passed"

    if "test_reflected_input_is_escaped" in name_lower:
        return "Reflected output escaping regression check passed"

    if "test_stored_comment" in name_lower or "test_multiple_stored_comments" in name_lower:
        return "Stored output escaping regression check passed"

    if "test_reflected_html_attribute_input_is_escaped" in name_lower:
        return "Reflected attribute-context escaping check passed"

    if "test_stored_html_attribute_input_is_escaped" in name_lower:
        return "Stored attribute-context escaping check passed"

    if "test_reflected_special_characters_are_escaped" in name_lower:
        return "Special-character escaping check passed"

    if "test_dashboard_requires_login" in name_lower:
        return "Dashboard access-control regression check passed"

    if "test_delete_security_event_requires_login" in name_lower:
        return "Security-event access-control regression check passed"

    if "test_run_security_tests_requires_login" in name_lower:
        return "Security-test access-control regression check passed"

    
    if "test_reflected_fixture_distinguishes_unsafe_and_safe_output" in name_lower:
        return (
            "PASS: Vulnerable output preserved raw HTML markup; "
            "safe output contained escaped HTML"
        )

    if "test_stored_fixture_distinguishes_unsafe_and_safe_output" in name_lower:
        return (
            "PASS: Vulnerable stored output preserved raw HTML markup; "
            "safe stored output contained escaped HTML"
        )

    if "test_reflected_fixture_verification_detects_potential_risk" in name_lower:
        return (
            "PASS: Verification classified vulnerable reflected output "
            "as POTENTIAL RISK"
        )

    if "test_stored_fixture_verification_accepts_safe_output" in name_lower:
        return (
            "PASS: Verification classified escaped stored output as SAFE"
        )

    return "Test passed; inspect its assertions for specific security evidence"

# --------------------------------------------------
# 1. Run existing pytest regression tests
# --------------------------------------------------
if report_json.exists():
    report_json.unlink()
pytest_result = subprocess.run(
    [
        sys.executable,
        "-m",
        "pytest",
        "--json-report",
        f"--json-report-file={report_json}",
        *pytest_files,
    ],
    cwd=PROJECT_DIR,
    capture_output=True,
    text=True,
)

print(pytest_result.stdout)

if pytest_result.stderr:
    print(pytest_result.stderr)

pytest_total = 0
pytest_passed = 0
pytest_failed = 0

if report_json.exists():
    try:
        data = json.loads(report_json.read_text(encoding="utf-8"))
        tests = data.get("tests", [])
        summary = data.get("summary", {})

        pytest_total = summary.get("total", len(tests))
        pytest_passed = summary.get("passed", 0)
        pytest_failed = summary.get("failed", 0)

        for test in tests:
            raw_outcome = test.get("outcome", "unknown").upper()

            if raw_outcome == "PASSED":
                outcome = "PASS"
            elif raw_outcome in ("FAILED", "ERROR"):
                outcome = "FAIL"
            elif raw_outcome == "SKIPPED":
                outcome = "SKIP"
            else:
                outcome = raw_outcome

            name = test.get("nodeid", "Unknown test")


            details = ""
            for phase in ("call", "setup", "teardown"):
                phase_data = test.get(phase, {})
                if phase_data.get("longrepr"):
                    details = str(phase_data["longrepr"])
                    break

            report_rows.append([
                generated_at,
                name,
                categorize_test(name),
                get_expected_behavior(name),
                outcome,
                get_security_outcome(name, outcome, details),
                get_remediation_status(name, outcome),
                details.replace("\n", " ")[:1000],
            ])

    except (json.JSONDecodeError, OSError) as error:
        errors.append(f"Could not read pytest report: {error}")
else:
    errors.append("Pytest JSON report was not generated.")

if pytest_result.returncode != 0:
    errors.append("The pytest command failed.")

# --------------------------------------------------
# 2. Run browser checks individually
# --------------------------------------------------
browser_total = 0
browser_passed = 0
browser_failed = 0

for test in browser_tests:
    test_file = test["file"]
    scenario = test.get("scenario")

    print(f"\nRunning browser test: {test['name']}", flush=True)

    try:
        if scenario:
            result = run_remediation_scenario(scenario)
        else:
            result = subprocess.run(
                [sys.executable, test_file],
                cwd=PROJECT_DIR,
                capture_output=True,
                text=True,
                timeout=60,
            )

        output = "\n".join(
            part for part in (result.stdout, result.stderr) if part
        )

        print(output)

        status = "PASS" if result.returncode == 0 else "FAIL"

        if result.returncode != 0:
            errors.append(f"Browser test failed: {test['name']}")

    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        status = "FAIL"
        output = str(error)
        errors.append(f"Could not run {test['name']}: {error}")

    browser_total += 1

    if status == "PASS":
        browser_passed += 1
    else:
        browser_failed += 1

    
    report_rows.append([
        generated_at,
        test["name"],
        test["category"],
        get_expected_behavior(test["name"]),
        status,
        get_security_outcome(test["name"], status, output),
        get_remediation_status(test["name"], status),
        output.replace("\n", " ")[:1000],
    ])


# --------------------------------------------------
# 3. Calculate overall results
# --------------------------------------------------
total = pytest_total + browser_total
passed = pytest_passed + browser_passed
failed = pytest_failed + browser_failed

overall_status = (
    "PASS"
    if not errors
    and pytest_result.returncode == 0
    and pytest_failed == 0
    and browser_failed == 0
    and pytest_total == pytest_passed
    else "FAIL"
)

# --------------------------------------------------
# 4. Write combined CSV report
# --------------------------------------------------
with report_csv.open("w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)

    
    writer.writerow([
        "Generated At",
        "Test Name",
        "Test Category",
        "Expected Behavior",
        "Test Result",
        "Security Outcome",
        "Remediation Status",
        "Evidence / Details",
    ])


    writer.writerows(report_rows)

    writer.writerow([])
    writer.writerow(["Total Tests", total])
    writer.writerow(["Passed", passed])
    writer.writerow(["Failed", failed])
    writer.writerow(["Overall Status", overall_status])
    writer.writerow([])
    writer.writerow(["REMEDIATION SUMMARY"])
    writer.writerow(["Check", "Result", "Details"])

    remediation_checks = [
        (
            "Vulnerable Fixture Detection",
            "Vulnerable Fixture Browser Test",
            "Script execution was detected in the intentionally vulnerable test fixture."
        ),
        (
            "Secured Fixture Verification",
            "Secured Fixture Remediation Test",
            "The secured fixture displayed the test input as text without executing the marker."
        ),
        (
            "Reflected XSS Verification",
            "Reflected XSS Browser Test",
            "The reflected input was displayed as text without executing the marker."
        ),
        (
            "Stored XSS Verification",
            "Stored XSS Browser Test",
            "The stored input was displayed as text without executing the marker."
        ),
    ]

    for check_name, test_name, details in remediation_checks:
        matching_rows = [
            row for row in report_rows
            if row[1] == test_name
        ]

        check_passed = (
            len(matching_rows) == 1
            and matching_rows[0][4] == "PASS"
        )

        result = "PASS" if check_passed else "FAIL"
        writer.writerow([check_name, result, details])

# --------------------------------------------------
# 5. Print summary
# --------------------------------------------------
print("\n========== COMBINED TEST SUMMARY ==========")
print(f"Pytest tests: {pytest_total}")
print(f"Pytest passed: {pytest_passed}")
print(f"Pytest failed: {pytest_failed}")
print(f"Browser checks: {browser_total}")
print(f"Browser passed: {browser_passed}")
print(f"Browser failed: {browser_failed}")
print(f"Total checks: {total}")
print(f"Total passed: {passed}")
print(f"Total failed: {failed}")
print(f"Overall Status: {overall_status}")
print(f"CSV report saved to: {report_csv}")

if errors:
    print("\nIssues:")
    for error in errors:
        print(f"- {error}")

sys.exit(0 if overall_status == "PASS" else 1)
