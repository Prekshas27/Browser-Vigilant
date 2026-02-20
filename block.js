document.addEventListener("DOMContentLoaded", () => {
    // Parse query params from content.js
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = decodeURIComponent(params.get("url") || "");
    const threat = params.get("threat") || "Unknown Threat";
    const rawSignals = decodeURIComponent(params.get("signals") || "");
    const signals = rawSignals ? rawSignals.split("|").filter(Boolean) : [];

    // Populate Threat Info
    document.getElementById("blockedUrl").textContent = blockedUrl || document.referrer || "Unknown";
    const displayThreat = signals.length > 0 ? signals.join(", ") : threat;
    document.getElementById("threatType").textContent = displayThreat;
    document.getElementById("threatTypeLabel").textContent = threat.toUpperCase();

    // Go back safely
    document.getElementById("btnGoBack").addEventListener("click", () => {
        if (window.history.length > 1) {
            window.history.back();
        } else {
            window.location.href = "chrome://newtab/";
        }
    });

    // Proceed anyway — warn and proceed
    document.getElementById("btnProceed").addEventListener("click", () => {
        if (confirm("⚠ WARNING: This page has been identified as dangerous.\n\nProceeding may expose you to phishing, malware, or fraud.\n\nAre you sure you want to continue?")) {
            try {
                const proceedUrl = new URL(blockedUrl);
                proceedUrl.searchParams.set("bv_allow", "1");
                window.location.href = proceedUrl.toString();
            } catch {
                window.location.href = blockedUrl;
            }
        }
    });
});
