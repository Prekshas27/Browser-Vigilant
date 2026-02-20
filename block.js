document.addEventListener("DOMContentLoaded", () => {
    // Parse query params from content.js
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = decodeURIComponent(params.get("url") || "");
    const risk = parseInt(params.get("risk") || "0", 10);
    const threat = params.get("threat") || "Unknown Threat";
    const rawSignals = decodeURIComponent(params.get("signals") || "");
    const signals = rawSignals ? rawSignals.split("|").filter(Boolean) : [];

    // Populate
    document.getElementById("blockedUrl").textContent = blockedUrl || document.referrer || "Unknown";
    document.getElementById("threatType").textContent = threat;
    document.getElementById("threatTypeLabel").textContent = threat.toUpperCase();
    document.getElementById("riskNum").textContent = `${risk}%`;
    document.getElementById("riskFill").style.width = `${Math.min(risk, 100)}%`;

    const list = document.getElementById("signalsList");
    (signals.length ? signals : ["Multi-layer threat analysis"]).forEach(sig => {
        const pill = document.createElement("div");
        pill.className = "signal-pill";
        pill.innerHTML = `<span class="signal-dot"></span>${sig}`;
        list.appendChild(pill);
    });

    // Go back safely
    document.getElementById("btnGoBack").addEventListener("click", () => {
        history.back();
    });

    // Proceed anyway — warn and proceed
    document.getElementById("btnProceed").addEventListener("click", () => {
        if (confirm("⚠ WARNING: This page has been identified as dangerous.\n\nProceeding may expose you to phishing, malware, or fraud.\n\nAre you sure you want to continue?")) {
            window.location.href = blockedUrl;
        }
    });
});
