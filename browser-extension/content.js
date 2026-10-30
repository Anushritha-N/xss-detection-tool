
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type !== "INSPECT_PAGE") {
        return;
    }

    try {
        const forms = Array.from(document.querySelectorAll("form"));

        const inputs = Array.from(
            document.querySelectorAll("input, textarea, select")
        ).filter(element => {
            const style = window.getComputedStyle(element);

            return (
                style.display !== "none" &&
                style.visibility !== "hidden" &&
                element.getClientRects().length > 0
            );
        });

        const inputDetails = inputs.map((element, index) => {
            const type =
                element instanceof HTMLInputElement
                    ? element.type
                    : element.tagName.toLowerCase() === "textarea"
                        ? "textarea"
                        : element.tagName.toLowerCase() === "select"
                            ? "select"
                            : "unknown";

            const form = element.form;

            return {
                number: index + 1,
                name: element.name || element.id || "(unnamed)",
                type: type,
                form: form
                    ? form.id || form.getAttribute("name") || "Form"
                    : "No associated form",
                required: element.required
            };
        });

        const passwordCount = inputs.filter(
            element =>
                element instanceof HTMLInputElement &&
                element.type.toLowerCase() === "password"
        ).length;

        const xssFindings = [];

        const suspiciousPatterns = [
            {
                name: "HTML tag pattern",
                regex: /<\s*\/?\s*[a-z][^>]*>/i,
                explanation:
                    "Input contains HTML-like markup. Check whether the application safely encodes it before displaying it."
            },
            {
                name: "Script-related pattern",
                regex: /<\s*script\b|javascript\s*:/i,
                explanation:
                    "Input contains a script-related pattern. Verify that it cannot execute when processed or rendered."
            },
            {
                name: "Event-handler pattern",
                regex: /\bon[a-z]+\s*=/i,
                explanation:
                    "Input resembles an HTML event-handler attribute. Check how the application handles and renders it."
            }
        ];

        inputs.forEach((element, index) => {
            const value = element.value;

            if (!value.trim()) {
                return;
            }

            suspiciousPatterns.forEach(pattern => {
                if (pattern.regex.test(value)) {
                    xssFindings.push({
                        field: element.name || element.id || `Input ${index + 1}`,
                        pattern: pattern.name,
                        explanation: pattern.explanation
                    });
                }
            });
        });

        const findings = [];

        forms.forEach((form, index) => {
            const method = (form.getAttribute("method") || "get").toLowerCase();

            if (method === "get") {
                findings.push({
                    title: `Form ${index + 1} uses GET`,
                    description:
                        "Submitted values may appear in the URL. " +
                        "Avoid placing sensitive information in GET requests."
                });
            }
        });

        inputs.forEach(element => {
            const isLabelable = element.matches(
                "input:not([type='hidden']), textarea, select"
            );

            if (!isLabelable) {
                return;
            }

            const hasExplicitLabel =
                element.id &&
                document.querySelector(
                    `label[for="${CSS.escape(element.id)}"]`
                );

            const hasWrappingLabel = element.closest("label");

            const hasAccessibleName =
                element.hasAttribute("aria-label") ||
                (element.hasAttribute("aria-labelledby") &&
                    element.getAttribute("aria-labelledby").trim() !== "");

            if (!hasExplicitLabel && !hasWrappingLabel && !hasAccessibleName) {
                findings.push({
                    title: `Input "${element.name || element.id || "unnamed"}" has no label`,
                    description:
                        "Consider adding an associated label or accessible name."
                });
            }
        });

        sendResponse({
            success: true,
            formCount: forms.length,
            inputCount: inputs.length,
            passwordCount: passwordCount,
            inputDetails: inputDetails,
            findings: findings,
            xssFindings: xssFindings
        });

    } catch (error) {
        sendResponse({
            success: false,
            error: "Unable to inspect this page."
        });
    }

    return true;
});
