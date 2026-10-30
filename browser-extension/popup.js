
const inspectButton = document.getElementById("inspect-button");
const statusTitle = document.getElementById("status-title");
const statusMessage = document.getElementById("status-message");
const results = document.getElementById("results");

inspectButton.addEventListener("click", async () => {
    inspectButton.disabled = true;
    statusTitle.textContent = "Inspecting page...";
    statusMessage.textContent = "Checking the current tab.";
    results.hidden = true;

    try {
        const [tab] = await chrome.tabs.query({
            active: true,
            currentWindow: true
        });

        if (!tab || !tab.id || !tab.url) {
            throw new Error("No active browser tab was found.");
        }

        const allowedPage =
            tab.url.startsWith("http://127.0.0.1:5000/") ||
            tab.url.startsWith("http://localhost:5000/");

        if (!allowedPage) {
            throw new Error(
                "For this prototype, open your local XSS app at " +
                "http://127.0.0.1:5000/"
            );
        }

        const response = await chrome.tabs.sendMessage(
            tab.id,
            { type: "INSPECT_PAGE" }
        );

        if (!response || !response.success) {
            throw new Error(
                response?.error || "The page inspection did not complete."
            );
        }

        document.getElementById("form-count").textContent =
            response.formCount;

        document.getElementById("input-count").textContent =
            response.inputCount;

        document.getElementById("password-count").textContent =
            response.passwordCount;

        
        document.getElementById("inspection-note").textContent =
            "Counts describe visible page structure only. " +
            "They do not prove that the page is vulnerable or secure.";

        const inputDetails = document.getElementById("input-details");
        inputDetails.replaceChildren();

        if (response.inputDetails && response.inputDetails.length > 0) {
            response.inputDetails.forEach(item => {
                const card = document.createElement("div");
                card.className = "input-detail-card";

                const heading = document.createElement("strong");
                heading.textContent = `${item.number}. ${item.name}`;

                const details = document.createElement("p");
                details.textContent =
                    `Type: ${item.type} | Form: ${item.form}`;

                const required = document.createElement("p");
                required.textContent = item.required
                    ? "Required: Yes"
                    : "Required: No";

                card.append(heading, details, required);
                inputDetails.appendChild(card);
            });
        } else {
            const emptyMessage = document.createElement("p");
            emptyMessage.textContent = "No visible input fields found.";
            inputDetails.appendChild(emptyMessage);
        }

        const findingsContainer = document.getElementById("security-findings");
        findingsContainer.replaceChildren();

        if (response.findings && response.findings.length > 0) {
            response.findings.forEach(finding => {
                const card = document.createElement("div");
                card.className = "finding-card";

                const heading = document.createElement("strong");
                heading.textContent = `⚠ ${finding.title}`;

                const description = document.createElement("p");
                description.textContent = finding.description;

                card.append(heading, description);
                findingsContainer.appendChild(card);
            });
        } else {
            const message = document.createElement("p");
            message.textContent = "No findings detected by these checks.";
            findingsContainer.appendChild(message);
        }

        latestInspectionReport = {
            page: tab.url,
            summary: {
                formsFound: response.formCount,
                inputFields: response.inputCount,
                passwordFields: response.passwordCount
            },
            inputDetails: response.inputDetails || [],
            findings: response.findings || [],
            xssFindings: response.xssFindings || []

        };

        const xssContainer = document.getElementById("xss-findings");
        xssContainer.replaceChildren();

        if (response.xssFindings && response.xssFindings.length > 0) {
            response.xssFindings.forEach(finding => {
                const card = document.createElement("div");
                card.className = "finding-card";

                const heading = document.createElement("strong");
                heading.textContent = `⚠ ${finding.pattern}`;

                const field = document.createElement("p");
                field.textContent = `Field: ${finding.field}`;

                const explanation = document.createElement("p");
                explanation.textContent = finding.explanation;

                card.append(heading, field, explanation);
                xssContainer.appendChild(card);
            });
        } else {
            const message = document.createElement("p");
            message.textContent =
                "No suspicious patterns detected in the current input values.";
            xssContainer.appendChild(message);
        }


        results.hidden = false;
        statusTitle.textContent = "Inspection complete";
        statusMessage.textContent = "The local page structure was inspected.";

    } catch (error) {
        statusTitle.textContent = "Inspection unavailable";
        statusMessage.textContent = error.message;
    } finally {
        inspectButton.disabled = false;
    }
});


let latestInspectionReport = null;

document.getElementById("download-report").addEventListener("click", () => {
    if (!latestInspectionReport) {
        statusTitle.textContent = "No report available";
        statusMessage.textContent =
            "Inspect a page first, then download the report.";
        return;
    }

    const report = {
        reportTitle: "XSS Security Inspector Report",
        generatedAt: new Date().toISOString(),
        page: latestInspectionReport.page,
        summary: latestInspectionReport.summary,
        
        inputDetails: latestInspectionReport.inputDetails,
        securityFindings: latestInspectionReport.findings,
        xssPatternFindings: latestInspectionReport.xssFindings,
        note: "These checks identify potential issues only; they do not prove XSS vulnerability or security."
    };

    const blob = new Blob(
        [JSON.stringify(report, null, 2)],
        { type: "application/json" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "xss-inspection-report.json";
    link.click();

    URL.revokeObjectURL(url);
});
