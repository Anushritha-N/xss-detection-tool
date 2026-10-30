# Cross-Site Scripting (XSS) Detection and Mitigation Tool

## 1. Project Overview

The **XSS Detection and Mitigation Tool** is a web-based security testing application designed to identify and demonstrate Cross-Site Scripting (XSS) vulnerabilities in a controlled environment.

The project focuses on reflected and stored XSS attacks. It provides vulnerable and secured test scenarios to demonstrate how malicious input can affect a web application and how appropriate input handling and output encoding can prevent script execution.

The tool also includes automated tests, a browser extension, and verification reports to evaluate detection and remediation.

## 2. Key Features

- **Reflected XSS Testing:** Tests whether user-supplied input is safely handled when displayed in a response.
- **Stored XSS Testing:** Tests whether submitted content is safely handled when stored and displayed later.
- **Vulnerable and Secure Test Fixtures:** Provides controlled environments to compare vulnerable behavior with secured behavior.
- **Automated Testing:** Uses automated test cases to verify detection and remediation.
- **Browser Extension:** Inspects web forms and input fields for selected suspicious patterns and configurations.
- **Security Monitoring:** Provides monitoring and test-result information through the application dashboard.
- **Verification Reports:** Generates a CSV report containing test results and remediation status.

## 3. Technologies Used

- Python
- Flask
- HTML and CSS
- JavaScript
- SQLite
- Pytest
- Browser automation tools

## 4. Project Structure

```text
xss-detection-tool/
│
├── app.py
├── xss_checks.py
├── xss_fixtures.py
├── security_monitor.py
├── evaluate_detection.py
│
├── vulnerable_test_fixture.py
├── secure_test_fixture.py
│
├── browser_detection_runner.py
├── browser_xss_tests.py
├── browser_stored_xss_tests.py
├── run_browser_tests.py
│
├── generate_report.py
│
├── browser-extension/
│   ├── content.js
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
│
├── templates/
├── static/
├── reports/
│
├── test_app.py
├── test_detection_matrix.py
├── test_remediation.py
├── test_security_monitor.py
├── test_vulnerable_fixture.py
├── test_xss_checks.py
├── test_xss_fixtures.py
│
├── start_app.bat
└── .gitignore
```

## 5. Setup and Installation

### Prerequisites

- Python 3.11 or later
- Git
- Visual Studio Code or another code editor
- A modern web browser

### Step 1: Clone the repository

```bash
git clone https://github.com/Anushritha-N/xss-detection-tool.git
cd xss-detection-tool
```

### Step 2: Create a virtual environment

```bash
python -m venv .venv
```

### Step 3: Activate the virtual environment

For Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### Step 4: Install dependencies

Install the Python packages required by the project:

```bash
pip install -r requirements.txt
```

Additional browser-testing dependencies may be required depending on the browser automation configuration.

## 6. Running the Application

On Windows, run:

```text
start_app.bat
```

Alternatively, activate the virtual environment and run:

```bash
python app.py
```

Open the application in your browser:

```text
http://127.0.0.1:5000
```

```bash
python -m playwright install chromium
```

## 7. Running Tests

To execute the automated test suite:

```bash
python -m pytest -v
```

The tests cover application behavior, XSS detection, fixture behavior, security monitoring, and remediation verification.

Browser-based tests can be executed using the project's browser test runner:

```bash
python run_browser_tests.py
```

The browser tests require the configured browser automation dependencies and a supported browser.

## 8. Generating Verification Reports

To generate the verification report, run:

```bash
python generate_report.py
```

The generated reports are stored in the `reports/` directory.

The CSV report includes test names, categories, expected behavior, test results, security outcomes, remediation status, and supporting details.

## 9. Security Testing and Expected Outcomes

The project uses controlled test scenarios to evaluate the handling of potentially malicious input.

| Test Scenario | Expected Outcome |
|---|---|
| Reflected XSS with unsafe input | Vulnerable behavior is identified in the controlled fixture |
| Reflected XSS with secured handling | Input is displayed safely without script execution |
| Stored XSS with unsafe input | Vulnerable behavior is identified in the controlled fixture |
| Stored XSS with secured handling | Stored input is displayed safely without script execution |
| Remediation verification | Secured behavior is confirmed through automated tests |

## 10. Limitations

- Testing is limited to the XSS scenarios and test cases implemented in this project.
- The browser extension uses selected patterns and configuration checks; it is not a comprehensive vulnerability scanner.
- Browser-based tests depend on the configured browser and automation environment.
- The project is intended for controlled security testing and educational demonstrations, not as a replacement for a professional web application security assessment.
- The application does not guarantee protection against every type of XSS vulnerability.

## 11. Responsible Use

This tool is intended for educational purposes and authorized security testing in controlled environments.

Only test applications and systems for which you have permission.

## 12. Author

**Anushritha N**

GitHub: [Anushritha-N](https://github.com/Anushritha-N)
