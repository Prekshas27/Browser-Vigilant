<script>
    /**
     * Shield.svelte — Current page scan result
     * All data comes from props (loaded from chrome.storage via App.svelte).
     * No hardcoded values anywhere.
     */
    /** @type {{ verdict:string, riskScore:number, mlProb:number|null, hScore:number,
     *  domScore:number, signals:string[], threatType:string|null,
     *  scanMs:number|null, url:string|null, features:number[] } | null} */
    export let tabState = null;

    /** @type {{ totalScanned:number, totalBlocked:number, threatsToday:number } | null} */
    export let stats = null;

    // Feature labels matching lib.rs/features.py index order (first 10 shown)
    const FEATURE_LABELS = [
        "URL Length",
        "Domain Length",
        "Path Length",
        "Query Length",
        "Dot Count",
        "Hyphen Count",
        "Underscore Count",
        "Slash Count",
        "At-Sign Count",
        "Digit Count",
    ];

    // Signal severity color
    function signalColor(signal) {
        const s = signal.toLowerCase();
        if (
            s.includes("credential") ||
            s.includes("clipboard") ||
            s.includes("upi fraud") ||
            s.includes("homograph") ||
            s.includes("overlay")
        )
            return "#ef4444";
        if (
            s.includes("brand") ||
            s.includes("tld") ||
            s.includes("punycode") ||
            s.includes("http") ||
            s.includes("ip address")
        )
            return "#f59e0b";
        return "#3b82f6";
    }

    function verdictColor(verdict) {
        if (verdict === "threat") return "#ef4444";
        if (verdict === "warning") return "#f59e0b";
        return "#10b981";
    }

    function verdictLabel(verdict) {
        if (verdict === "threat") return "Threat Blocked";
        if (verdict === "warning") return "Warning";
        return "Site is Safe";
    }

    function verdictIcon(verdict) {
        if (verdict === "threat") return "🚫";
        if (verdict === "warning") return "⚠️";
        return "✅";
    }

    function riskColor(score) {
        if (score >= 70) return "#ef4444";
        if (score >= 40) return "#f59e0b";
        return "#10b981";
    }

    // Format ML probability as percentage string
    function fmtProb(p) {
        if (p === null || p === undefined) return "N/A";
        return `${(p * 100).toFixed(1)}%`;
    }

    $: verdict = tabState?.verdict ?? null;
    $: riskScore = tabState?.riskScore ?? 0;
    $: mlProb = tabState?.mlProb ?? null;
    $: hScore = tabState?.hScore ?? 0;
    $: domScore = tabState?.domScore ?? 0;
    $: signals = tabState?.signals ?? [];
    $: threatType = tabState?.threatType ?? null;
    $: scanMs = tabState?.scanMs ?? null;
    $: currentUrl = tabState?.url ?? null;
    $: features = tabState?.features ?? [];

    // ── Quick URL scanner (popup-side heuristics, no content script required) ──
    let scanInput = "";
    let scanResult = null; // { verdict, riskScore, signals, threatType }
    let scanning = false;

    const SCAN_BRANDS = [
        "google",
        "facebook",
        "amazon",
        "apple",
        "microsoft",
        "paypal",
        "netflix",
        "instagram",
        "twitter",
        "linkedin",
        "youtube",
        "yahoo",
        "ebay",
        "coinbase",
        "binance",
        "paytm",
        "hdfc",
        "icici",
        "sbi",
        "flipkart",
    ];
    const SCAN_SUSP_TLDS = new Set([
        "xyz",
        "tk",
        "top",
        "cf",
        "ml",
        "ga",
        "gq",
        "pw",
        "cc",
        "icu",
        "club",
        "online",
        "site",
        "space",
        "live",
        "click",
        "link",
        "info",
    ]);
    const SCAN_LOGIN_KW = [
        "login",
        "signin",
        "verify",
        "account",
        "auth",
        "confirm",
        "update",
        "secure",
    ];
    const SCAN_FREE_KW = [
        "free",
        "prize",
        "winner",
        "claim",
        "reward",
        "lucky",
        "giveaway",
        "bonus",
    ];

    function scanLev(a, b) {
        const m = a.length,
            n = b.length;
        let prev = Array.from({ length: n + 1 }, (_, i) => i);
        for (let i = 1; i <= m; i++) {
            const c = [i];
            for (let j = 1; j <= n; j++)
                c[j] = Math.min(
                    prev[j] + 1,
                    c[j - 1] + 1,
                    prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
                );
            prev = c;
        }
        return prev[n];
    }

    function quickScan(url) {
        let score = 0;
        const sigs = [];
        const low = url.toLowerCase().trim();

        let host = "",
            tld = "",
            domain = "",
            path = "",
            scheme = "";
        try {
            const u = new URL(low.startsWith("http") ? low : "https://" + low);
            host = u.hostname;
            path = u.pathname;
            tld = host.split(".").pop();
            domain = host.split(".").slice(-2).join(".");
            scheme = u.protocol.replace(":", "");
        } catch {
            return {
                verdict: "error",
                riskScore: 0,
                signals: ["Invalid URL"],
                threatType: "Parse Error",
            };
        }

        if (host.includes("xn--")) {
            score += 0.9;
            sigs.push("Punycode / IDN Homograph");
        }
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
            score += 0.85;
            sigs.push("IP Address in URL");
        }
        if (SCAN_SUSP_TLDS.has(tld)) {
            score += 0.6;
            sigs.push(`Suspicious TLD (.${tld})`);
        }
        if (scheme !== "https") {
            score += 0.3;
            sigs.push("Not HTTPS");
        }
        if ((url.match(/@/g) || []).length > 1) {
            score += 0.8;
            sigs.push("Multiple @ Symbols");
        }
        if (host.split(".").length >= 5) {
            score += 0.5;
            sigs.push("Excessive Subdomain Depth");
        }
        if (SCAN_LOGIN_KW.some((k) => low.includes(k)) && scheme !== "https") {
            score += 0.55;
            sigs.push("Login Keywords on HTTP");
        }
        if (SCAN_FREE_KW.some((k) => low.includes(k))) {
            score += 0.55;
            sigs.push("Prize/Scam Keywords");
        }
        if (/upi|gpay|bhim|paytm/i.test(low)) {
            score += 0.3;
            sigs.push("UPI Payment Keywords");
        }
        if (/\.exe|\.scr|\.bat|\.ps1|\.vbs/i.test(path)) {
            score += 0.75;
            sigs.push("Executable File Extension");
        }
        if (/(%[0-9a-f]{2}){4,}/i.test(url)) {
            score += 0.45;
            sigs.push("Heavy URL Encoding");
        }

        const core = domain.split(".")[0] || "";
        const minD = Math.min(...SCAN_BRANDS.map((b) => scanLev(core, b)));
        if (minD > 0 && minD <= 2) {
            score += 0.8;
            sigs.push(`Brand Spoof (${core} ≈ known brand)`);
        }

        const total = Math.min(Math.round(score * 100), 100);
        let verdict = total >= 50 ? "threat" : total >= 30 ? "warning" : "safe";
        let threatType = sigs.length ? sigs[0] : "Clean";
        return { verdict, riskScore: total, signals: sigs, threatType };
    }

    function handleScan() {
        if (!scanInput.trim()) return;
        scanning = true;
        setTimeout(() => {
            scanResult = quickScan(scanInput.trim());
            scanning = false;
        }, 400); // slight delay for UX
    }

    function handleKey(e) {
        if (e.key === "Enter") handleScan();
    }

    function clearScan() {
        scanInput = "";
        scanResult = null;
    }
</script>

<div class="shield-wrap">
    <!-- ── URL Scanner input ── -->
    <div class="scan-input-wrap">
        <div class="scan-bar">
            <span class="scan-icon">🔍</span>
            <input
                id="url-scan-input"
                class="scan-field"
                type="url"
                placeholder="Paste any URL to scan…"
                bind:value={scanInput}
                on:keydown={handleKey}
                spellcheck="false"
                autocomplete="off"
            />
            {#if scanInput}
                <button class="scan-clear" on:click={clearScan} title="Clear"
                    >✕</button
                >
            {/if}
            <button
                class="scan-btn"
                on:click={handleScan}
                disabled={!scanInput.trim() || scanning}
            >
                {scanning ? "…" : "Scan"}
            </button>
        </div>

        {#if scanResult}
            <div class="scan-result-card verdict-{scanResult.verdict}">
                <div class="sr-top">
                    <span class="sr-emoji"
                        >{scanResult.verdict === "threat"
                            ? "🚫"
                            : scanResult.verdict === "warning"
                              ? "⚠️"
                              : "✅"}</span
                    >
                    <div class="sr-info">
                        <span class="sr-label"
                            >{scanResult.verdict === "threat"
                                ? "Threat Detected"
                                : scanResult.verdict === "warning"
                                  ? "Suspicious"
                                  : "Looks Safe"}</span
                        >
                        <span class="sr-type">{scanResult.threatType}</span>
                    </div>
                    <span
                        class="sr-score"
                        style="color:{scanResult.riskScore >= 50
                            ? '#ef4444'
                            : scanResult.riskScore >= 30
                              ? '#f59e0b'
                              : '#10b981'}"
                    >
                        {scanResult.riskScore}<small>/100</small>
                    </span>
                </div>
                {#if scanResult.signals.length > 0}
                    <div class="sr-signals">
                        {#each scanResult.signals as sig}
                            <span class="sr-chip">{sig}</span>
                        {/each}
                    </div>
                {:else}
                    <p class="sr-clean">No threat signals detected.</p>
                {/if}
            </div>
        {/if}
    </div>

    <div class="divider"></div>

    <!-- URL pill (current tab) -->
    {#if currentUrl}
        <div class="url-pill">
            <span
                class="url-scheme {currentUrl.startsWith('https')
                    ? 'https'
                    : 'http'}"
            >
                {currentUrl.startsWith("https") ? "🔒" : "⚠"}
            </span>
            <span class="url-text"
                >{currentUrl.length > 40
                    ? currentUrl.slice(0, 37) + "…"
                    : currentUrl}</span
            >
        </div>
    {/if}

    <!-- Status block -->
    <div
        class="status-block"
        style="--vc:{verdict ? verdictColor(verdict) : '#3b82f6'}"
    >
        {#if !tabState}
            <!-- No scan yet for this tab -->
            <div class="status-icon-wrap">
                <svg width="38" height="38" viewBox="0 0 24 24" fill="none">
                    <path
                        d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"
                        fill="rgba(59,130,246,0.15)"
                        stroke="#3b82f6"
                        stroke-width="1.5"
                    />
                    <path
                        d="M12 8v4M12 16h.01"
                        stroke="#3b82f6"
                        stroke-width="1.8"
                        stroke-linecap="round"
                    />
                </svg>
            </div>
            <p class="status-label">Standby</p>
            <p class="status-sub">Navigate to a page to begin scanning</p>
        {:else}
            <div
                class="status-icon-wrap"
                style="background: color-mix(in srgb, {verdictColor(
                    verdict,
                )} 12%, transparent)"
            >
                <span class="status-emoji">{verdictIcon(verdict)}</span>
            </div>
            <p class="status-label">{verdictLabel(verdict)}</p>
            {#if threatType && verdict === "threat"}
                <span class="threat-type-badge">{threatType}</span>
            {/if}
            <p class="status-sub">
                {#if scanMs !== null}Scanned in {scanMs}ms ·{/if}
                {#if mlProb !== null}ML: {fmtProb(mlProb)} ·{/if}
                Risk: {riskScore}/100
            </p>
        {/if}
    </div>

    {#if tabState}
        <!-- Score tiles -->
        <div class="score-grid">
            <div class="score-tile">
                <span class="score-val" style="color:{riskColor(riskScore)}"
                    >{riskScore}</span
                >
                <span class="score-lbl">Risk Score</span>
                <div class="score-bar-bg">
                    <div
                        class="score-bar-fill"
                        style="width:{riskScore}%; background:{riskColor(
                            riskScore,
                        )}"
                    ></div>
                </div>
            </div>
            <div class="score-tile">
                <span
                    class="score-val"
                    style="color:{riskColor(Math.round(hScore * 100))}"
                    >{(hScore * 100).toFixed(0)}</span
                >
                <span class="score-lbl">Heuristic</span>
                <div class="score-bar-bg">
                    <div
                        class="score-bar-fill"
                        style="width:{hScore * 100}%; background:{riskColor(
                            Math.round(hScore * 100),
                        )}"
                    ></div>
                </div>
            </div>
            <div class="score-tile">
                <span
                    class="score-val"
                    style="color:{riskColor(Math.round(domScore * 100))}"
                    >{(domScore * 100).toFixed(0)}</span
                >
                <span class="score-lbl">DOM Score</span>
                <div class="score-bar-bg">
                    <div
                        class="score-bar-fill"
                        style="width:{domScore * 100}%; background:{riskColor(
                            Math.round(domScore * 100),
                        )}"
                    ></div>
                </div>
            </div>
            <div class="score-tile">
                <span
                    class="score-val"
                    style="color:{mlProb !== null
                        ? riskColor(Math.round(mlProb * 100))
                        : 'var(--text-muted)'}"
                >
                    {mlProb !== null ? (mlProb * 100).toFixed(0) : "—"}
                </span>
                <span class="score-lbl">ML Prob %</span>
                <div class="score-bar-bg">
                    <div
                        class="score-bar-fill"
                        style="width:{mlProb !== null
                            ? mlProb * 100
                            : 0}%; background:{mlProb !== null
                            ? riskColor(Math.round(mlProb * 100))
                            : 'var(--text-muted)'}"
                    ></div>
                </div>
            </div>
        </div>

        <!-- Signals (Explainable AI) -->
        {#if signals.length > 0}
            <div class="section-card">
                <div class="section-hdr">
                    <span class="section-title">Threat Signals</span>
                    <span class="badge badge-blue">Explainable AI</span>
                </div>
                <div class="signals-list">
                    {#each signals as sig}
                        <div class="signal-row">
                            <span
                                class="signal-dot"
                                style="background:{signalColor(
                                    sig,
                                )}; box-shadow:0 0 6px {signalColor(sig)}"
                            ></span>
                            <span class="signal-text">{sig}</span>
                        </div>
                    {/each}
                </div>
            </div>
        {/if}

        <!-- WASM Feature vector (first 10) -->
        {#if features && features.length > 0}
            <div class="section-card">
                <div class="section-hdr">
                    <span class="section-title">Feature Vector</span>
                    <span class="badge badge-blue">Rust WASM · 48 total</span>
                </div>
                <p class="section-sub">Raw values fed into the ML ensemble</p>
                <div class="feature-grid">
                    {#each features.slice(0, 10) as val, i}
                        <div class="feat-row">
                            <span class="feat-label"
                                >{FEATURE_LABELS[i] ?? `F[${i}]`}</span
                            >
                            <div class="feat-bar-bg">
                                <div
                                    class="feat-bar-fill"
                                    style="width:{Math.min(
                                        (val / 20) * 100,
                                        100,
                                    )}%"
                                ></div>
                            </div>
                            <span class="feat-val"
                                >{typeof val === "number"
                                    ? val.toFixed(2)
                                    : val}</span
                            >
                        </div>
                    {/each}
                </div>
            </div>
        {/if}
    {/if}

    <!-- Global stats -->
    {#if stats}
        <div class="global-stats">
            <div class="gs-item">
                <span class="gs-num">{stats?.totalScanned ?? 0}</span>
                <span class="gs-lbl">Total</span>
            </div>
            <div class="gs-item">
                <span class="gs-num" style="color:var(--accent-red)"
                    >{stats?.totalBlocked ?? 0}</span
                >
                <span class="gs-lbl">Blocked</span>
            </div>
            <div class="gs-item">
                <span class="gs-num" style="color:var(--accent-amber)"
                    >{stats?.threatsToday ?? 0}</span
                >
                <span class="gs-lbl">Today</span>
            </div>
        </div>
    {/if}
</div>

<style>
    .shield-wrap {
        display: flex;
        flex-direction: column;
        gap: 11px;
    }

    /* ── URL Scanner ── */
    .scan-input-wrap {
        display: flex;
        flex-direction: column;
        gap: 8px;
    }
    .scan-bar {
        display: flex;
        align-items: center;
        gap: 6px;
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 5px 8px;
        transition: border-color 0.2s;
    }
    .scan-bar:focus-within {
        border-color: var(--accent);
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.12);
    }
    .scan-icon {
        font-size: 13px;
        flex-shrink: 0;
        opacity: 0.5;
    }
    .scan-field {
        flex: 1;
        background: transparent;
        border: none;
        outline: none;
        color: var(--text-primary);
        font-family: var(--font-mono);
        font-size: 10px;
        min-width: 0;
    }
    .scan-field::placeholder {
        color: var(--text-muted);
    }
    .scan-clear {
        background: none;
        border: none;
        color: var(--text-muted);
        cursor: pointer;
        font-size: 11px;
        padding: 1px 4px;
        border-radius: 4px;
        flex-shrink: 0;
        transition: color 0.15s;
    }
    .scan-clear:hover {
        color: var(--text-primary);
    }
    .scan-btn {
        background: var(--accent);
        border: none;
        color: #fff;
        font-family: var(--font-main);
        font-size: 10px;
        font-weight: 700;
        padding: 5px 12px;
        border-radius: 7px;
        cursor: pointer;
        transition: all 0.18s;
        flex-shrink: 0;
        letter-spacing: 0.04em;
    }
    .scan-btn:hover:not(:disabled) {
        background: #2563eb;
        box-shadow: 0 0 12px rgba(59, 130, 246, 0.4);
    }
    .scan-btn:disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    /* Result card */
    .scan-result-card {
        border-radius: 10px;
        overflow: hidden;
        border: 1px solid;
        animation: slideIn 0.25s ease;
    }
    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateY(-6px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    .verdict-safe {
        border-color: rgba(16, 185, 129, 0.3);
        background: rgba(16, 185, 129, 0.05);
    }
    .verdict-warning {
        border-color: rgba(245, 158, 11, 0.3);
        background: rgba(245, 158, 11, 0.05);
    }
    .verdict-threat {
        border-color: rgba(239, 68, 68, 0.3);
        background: rgba(239, 68, 68, 0.05);
    }
    .verdict-error {
        border-color: rgba(156, 163, 175, 0.3);
        background: rgba(156, 163, 175, 0.05);
    }

    .sr-top {
        display: flex;
        align-items: center;
        gap: 9px;
        padding: 9px 11px;
    }
    .sr-emoji {
        font-size: 18px;
        flex-shrink: 0;
    }
    .sr-info {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .sr-label {
        font-size: 12px;
        font-weight: 700;
        color: var(--text-primary);
    }
    .sr-type {
        font-size: 9px;
        font-family: var(--font-mono);
        color: var(--text-muted);
    }
    .sr-score {
        font-size: 18px;
        font-weight: 800;
        font-family: var(--font-mono);
    }
    .sr-score small {
        font-size: 9px;
        opacity: 0.6;
    }

    .sr-signals {
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
        padding: 7px 11px;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
    }
    .sr-chip {
        font-size: 9px;
        padding: 2px 8px;
        border-radius: 100px;
        background: rgba(239, 68, 68, 0.08);
        border: 1px solid rgba(239, 68, 68, 0.2);
        color: var(--accent-red);
        font-family: var(--font-mono);
    }
    .sr-clean {
        font-size: 10px;
        color: var(--accent-green);
        padding: 6px 11px;
        font-family: var(--font-mono);
    }

    .divider {
        height: 1px;
        background: var(--border);
        margin: 2px 0;
    }

    .url-pill {
        display: flex;
        align-items: center;
        gap: 6px;
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 6px 11px;
    }
    .url-scheme {
        font-size: 12px;
    }
    .url-scheme.http {
        filter: opacity(0.6);
    }
    .url-text {
        font-family: var(--font-mono);
        font-size: 10px;
        color: var(--text-secondary);
        flex: 1;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .status-block {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 7px;
        padding: 18px 16px;
        border-radius: 14px;
        border: 1px solid color-mix(in srgb, var(--vc) 25%, transparent);
        background: color-mix(in srgb, var(--vc) 5%, transparent);
        transition: all 0.25s;
    }
    .status-block[style*="#ef4444"] {
        animation: tPulse 2s ease infinite;
    }
    @keyframes tPulse {
        0%,
        100% {
            box-shadow: 0 0 0 0 rgba(239, 68, 68, 0);
        }
        50% {
            box-shadow: 0 0 18px 2px rgba(239, 68, 68, 0.12);
        }
    }
    .status-icon-wrap {
        width: 62px;
        height: 62px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .status-emoji {
        font-size: 28px;
    }
    .status-label {
        font-size: 15px;
        font-weight: 700;
        color: var(--text-primary);
    }
    .status-sub {
        font-size: 10px;
        color: var(--text-muted);
        font-family: var(--font-mono);
        text-align: center;
    }
    .threat-type-badge {
        font-size: 9px;
        padding: 2px 9px;
        border-radius: 100px;
        background: rgba(239, 68, 68, 0.12);
        border: 1px solid rgba(239, 68, 68, 0.3);
        color: var(--accent-red);
        font-family: var(--font-mono);
        font-weight: 600;
        letter-spacing: 0.04em;
    }

    .score-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 7px;
    }
    .score-tile {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 8px 5px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 3px;
    }
    .score-val {
        font-size: 15px;
        font-weight: 700;
        font-family: var(--font-mono);
    }
    .score-lbl {
        font-size: 7.5px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.05em;
        text-align: center;
    }
    .score-bar-bg {
        width: 100%;
        height: 3px;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 100px;
        overflow: hidden;
        margin-top: 2px;
    }
    .score-bar-fill {
        height: 100%;
        border-radius: 100px;
        transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .section-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 11px 12px;
        display: flex;
        flex-direction: column;
        gap: 8px;
    }
    .section-hdr {
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .section-title {
        font-size: 11px;
        font-weight: 600;
        color: var(--text-primary);
    }
    .section-sub {
        font-size: 9px;
        color: var(--text-muted);
        font-family: var(--font-mono);
        margin-top: -4px;
    }

    .signals-list {
        display: flex;
        flex-direction: column;
        gap: 5px;
    }
    .signal-row {
        display: flex;
        align-items: center;
        gap: 7px;
    }
    .signal-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        flex-shrink: 0;
    }
    .signal-text {
        font-size: 10px;
        color: var(--text-secondary);
        font-family: var(--font-mono);
    }

    .feature-grid {
        display: flex;
        flex-direction: column;
        gap: 4px;
    }
    .feat-row {
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .feat-label {
        font-size: 9px;
        color: var(--text-muted);
        width: 82px;
        flex-shrink: 0;
        font-family: var(--font-mono);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .feat-bar-bg {
        flex: 1;
        height: 4px;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 100px;
        overflow: hidden;
    }
    .feat-bar-fill {
        height: 100%;
        background: var(--accent);
        border-radius: 100px;
        opacity: 0.7;
        transition: width 0.5s;
    }
    .feat-val {
        font-size: 9px;
        color: var(--text-muted);
        width: 28px;
        text-align: right;
        font-family: var(--font-mono);
    }

    .global-stats {
        display: flex;
        justify-content: space-around;
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 9px 8px;
    }
    .gs-item {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 1px;
    }
    .gs-num {
        font-size: 14px;
        font-weight: 700;
        font-family: var(--font-mono);
        color: var(--accent);
    }
    .gs-lbl {
        font-size: 8px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
</style>
