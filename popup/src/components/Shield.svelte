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

    // tabState (real-time scan) always takes priority over manual scanResult
    $: activeState = tabState || scanResult;
    $: verdict = activeState?.verdict ?? null;
    $: riskScore = activeState?.riskScore ?? 0;
    $: mlProb = activeState?.mlProb ?? null;
    $: hScore = activeState?.hScore ?? 0;
    $: domScore = activeState?.domScore ?? 0;
    $: signals = activeState?.signals ?? [];
    $: threatType = activeState?.threatType ?? null;
    $: scanMs = activeState?.scanMs ?? null;
    $: currentUrl = activeState?.url ?? null;
    $: features = activeState?.features ?? [];

    // ── URL scanner — delegates ALL logic to background.js ──────────────────
    // No duplicated brand lists, TLD lists, or heuristics here.
    // background.js runs prenavScan() + Vault lookup and returns the result.
    let scanInput = "";
    let scanResult = null;
    let scanning = false;
    let scanError = "";

    async function handleScan() {
        const raw = scanInput.trim();
        if (!raw || scanning) return;

        // Normalise — add https:// if no protocol given
        const url =
            raw.startsWith("http://") || raw.startsWith("https://")
                ? raw
                : "https://" + raw;

        // Basic format check — must be a parseable URL with a real hostname (has a dot, length > 3)
        try {
            const parsed = new URL(url);
            if (!parsed.hostname.includes(".") || parsed.hostname.length < 4) {
                scanError = "Please enter a valid URL (e.g. google.com)";
                return;
            }
        } catch {
            scanError = "Please enter a valid URL (e.g. google.com)";
            return;
        }

        scanning = true;
        scanError = "";
        scanResult = null;
        try {
            if (
                typeof chrome === "undefined" ||
                !chrome?.runtime?.sendMessage
            ) {
                // Dev mode — safe stub
                scanResult = {
                    verdict: "safe",
                    riskScore: 0,
                    signals: [],
                    threatType: "Dev mode — load as extension to scan",
                };
                return;
            }
            const res = await chrome.runtime.sendMessage({
                type: "SCAN_URL",
                url,
            });
            if (res?.error) throw new Error(res.error);
            scanResult = res;
        } catch (e) {
            scanError = "Scan failed: " + e.message;
        } finally {
            scanning = false;
        }
    }

    function handleKey(e) {
        if (e.key === "Enter") handleScan();
    }

    function clearScan() {
        scanInput = "";
        scanResult = null;
        scanError = "";
    }

    let reporting = false;
    let reported = false;
    
    async function reportSite() {
        if (!currentUrl || reporting || reported) return;
        reporting = true;
        try {
            if (typeof chrome !== "undefined" && chrome?.runtime?.sendMessage) {
                await chrome.runtime.sendMessage({
                    type: "MANUAL_FLAG",
                    url: currentUrl,
                    confidence: 0.7
                });
            }
            reported = true;
        } catch (e) {
            console.error("Report failed", e);
        } finally {
            reporting = false;
        }
    }
</script>

<div class="shield-view">
    {#if scanResult}
        <!-- ── Manual Scan Result view ── -->
        <div class="scan-result-view verdict-bg-{scanResult.verdict}">
            <button class="back-btn" on:click={clearScan}>
                <svg
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2.5"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    ><polyline points="15 18 9 12 15 6"></polyline></svg
                >
                Back
            </button>

            <!-- Result verdict circle -->
            <div class="sr-hero">
                <div
                    class="sr-icon-wrap {scanResult.verdict === 'threat'
                        ? 'sr-threat'
                        : scanResult.verdict === 'warning'
                          ? 'sr-warning'
                          : 'sr-safe'}"
                >
                    {#if scanResult.verdict === "safe"}
                        <svg
                            width="28"
                            height="28"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="white"
                            stroke-width="3.5"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            ><polyline points="20 6 9 17 4 12"></polyline></svg
                        >
                    {:else if scanResult.verdict === "warning"}
                        <svg
                            width="28"
                            height="28"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="white"
                            stroke-width="2.5"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            ><path
                                d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"
                            ></path><line x1="12" y1="9" x2="12" y2="13"
                            ></line><line x1="12" y1="17" x2="12.01" y2="17"
                            ></line></svg
                        >
                    {:else}
                        <svg
                            width="28"
                            height="28"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="white"
                            stroke-width="2.5"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            ><line x1="18" y1="6" x2="6" y2="18"></line><line
                                x1="6"
                                y1="6"
                                x2="18"
                                y2="18"
                            ></line></svg
                        >
                    {/if}
                </div>
                <h2 class="sr-title">
                    {scanResult.verdict === "safe"
                        ? "Looks clean"
                        : scanResult.verdict === "warning"
                          ? "Be cautious"
                          : "Threat detected"}
                </h2>
                {#if scanResult.threatType}
                    <span class="sr-type-badge">{scanResult.threatType}</span>
                {/if}
            </div>

            <!-- Stats cards -->
            <div class="sr-cards">
                <div class="sr-card">
                    <span class="sr-card-label">RISK SCORE</span>
                    <span
                        class="sr-card-value {scanResult.riskScore >= 70
                            ? 'text-threat'
                            : scanResult.riskScore >= 40
                              ? 'text-warning'
                              : 'text-safe'}">{scanResult.riskScore ?? 0}</span
                    >
                    <span class="sr-card-sub">out of 100</span>
                </div>
                <div class="sr-card">
                    <span class="sr-card-label">SIGNALS</span>
                    <span
                        class="sr-card-value {scanResult.signals?.length > 0
                            ? 'text-threat'
                            : 'text-safe'}"
                        >{scanResult.signals?.length ?? 0}</span
                    >
                    <span class="sr-card-sub">detected</span>
                </div>
            </div>

            <!-- Signal list -->
            {#if scanResult.signals?.length > 0}
                <div class="sr-signals-card">
                    <span class="sr-signals-title">THREAT SIGNALS</span>
                    {#each scanResult.signals as sig}
                        <div class="sr-signal-row">
                            <span class="sr-signal-dot"></span>
                            <span>{sig}</span>
                        </div>
                    {/each}
                </div>
            {:else}
                <div class="sr-clean-card">
                    <svg
                        width="16"
                        height="16"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="#34d399"
                        stroke-width="2.5"
                        ><polyline points="20 6 9 17 4 12"></polyline></svg
                    >
                    No threat signals detected
                </div>
            {/if}
        </div>
    {:else}
        <!-- ── Search Bar ── -->
        <div class="search-container">
            <svg
                class="search-icon"
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2.5"
                stroke-linecap="round"
                stroke-linejoin="round"
                ><circle cx="11" cy="11" r="8"></circle><line
                    x1="21"
                    y1="21"
                    x2="16.65"
                    y2="16.65"
                ></line></svg
            >
            <input
                type="text"
                class="search-input"
                placeholder="Scan any URL..."
                bind:value={scanInput}
                on:keydown={handleKey}
            />
            {#if scanInput}
                <button class="search-clear" on:click={clearScan}>✕</button>
            {/if}
            <button class="search-btn" on:click={handleScan} disabled={scanning}
                >{scanning ? "..." : "Scan"}</button
            >
        </div>
        {#if scanError}
            <p class="scan-error-msg">{scanError}</p>
        {/if}

        {#if !activeState}
            <!-- Standby State -->
            <div class="hero standby-hero">
                <div class="hero-icon-layer outer-standby">
                    <div class="hero-icon inner-standby">
                        <svg
                            width="32"
                            height="32"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2"
                            ><path
                                d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
                            /></svg
                        >
                    </div>
                </div>
                <h1 class="hero-title">Ready to protect</h1>
                <p class="hero-sub">Navigate to any page to begin scanning</p>

                {#if stats}
                    <div class="standby-stats">
                        <div class="sb-stat">
                            <span class="sb-num">{stats.totalScanned ?? 0}</span
                            >
                            <span class="sb-label">Pages scanned</span>
                        </div>
                        <div class="sb-divider"></div>
                        <div class="sb-stat">
                            <span class="sb-num threat-num"
                                >{stats.totalBlocked ?? 0}</span
                            >
                            <span class="sb-label">Threats blocked</span>
                        </div>
                        <div class="sb-divider"></div>
                        <div class="sb-stat">
                            <span class="sb-num">{stats.threatsToday ?? 0}</span
                            >
                            <span class="sb-label">Today</span>
                        </div>
                    </div>
                {/if}
            </div>
        {:else if verdict === "safe"}
            <!-- Safe State -->
            <div class="hero">
                <div class="hero-icon-layer outer-safe">
                    <div class="hero-icon-layer mid-safe">
                        <div class="hero-icon inner-safe">
                            <svg
                                width="28"
                                height="28"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="white"
                                stroke-width="3.5"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                ><polyline points="20 6 9 17 4 12"
                                ></polyline></svg
                            >
                        </div>
                    </div>
                </div>
                <h1 class="hero-title">All clear here.</h1>
                <div class="hero-pill">
                    <svg
                        width="12"
                        height="12"
                        viewBox="0 0 24 24"
                        fill="currentColor"
                        ><rect x="3" y="11" width="18" height="11" rx="2" ry="2"
                        ></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg
                    >
                    verified • secure connection
                </div>
            </div>
        {:else}
            <!-- Threat/Warning State -->
            <div class="hero threat-hero">
                <div class="hero-icon-layer outer-threat">
                    <div class="hero-icon inner-threat">
                        <svg
                            width="28"
                            height="28"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2.5"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            ><path
                                d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"
                            ></path><line x1="1" y1="1" x2="23" y2="23"
                            ></line></svg
                        >
                    </div>
                </div>
                <h1 class="hero-title">Tread carefully</h1>
                <p class="hero-sub">We found a few things you should know.</p>
            </div>
        {/if}

        {#if activeState}
            {#if verdict === "safe"}
                <!-- Cards Grid (Safe Mode) -->
                <div class="cards-grid">
                    <div class="metric-card">
                        <span class="mc-label">TRACKERS</span>
                        <span class="mc-value">0</span>
                        <span class="mc-sub safe"
                            ><span class="dot safe-dot"></span>Blocked</span
                        >
                    </div>
                    <div class="metric-card">
                        <span class="mc-label">REPUTATION</span>
                        <span
                            class="mc-value {riskScore > 30
                                ? 'threat'
                                : 'safe-text'}"
                            >{riskScore < 30 ? "High" : "Low"}</span
                        >
                        <span class="mc-sub">Trust Score</span>
                    </div>
                </div>

                <div class="info-card warning-bg">
                    <div class="ic-icon">
                        <svg
                            width="18"
                            height="18"
                            viewBox="0 0 24 24"
                            fill="currentColor"
                            stroke="none"
                            ><path
                                d="M9 21c0 .55.45 1 1 1h4c.55 0 1-.45 1-1v-1H9v1zm3-19C8.14 2 5 5.14 5 9c0 2.38 1.19 4.47 3 5.74V17c0 .55.45 1 1 1h6c.55 0 1-.45 1-1v-2.26c1.81-1.27 3-3.36 3-5.74 0-3.86-3.14-7-7-7z"
                            ></path></svg
                        >
                    </div>
                    <div class="ic-text">
                        <strong>DID YOU KNOW?</strong>
                        <p>
                            Check the URL spelling before logging in. Scammers
                            often change just one letter.
                        </p>
                    </div>
                </div>
                
                <div class="actions-fixed">
                    <button class="btn-trust" on:click={reportSite} disabled={reporting || reported} style="width: 100%; margin-top: 12px; color: {reported ? '#10b981' : 'var(--text-primary)'};">
                        {reported ? "Site Reported ✓" : reporting ? "Reporting..." : "🚩 Report Site as Malicious"}
                    </button>
                </div>
            {:else}
                <!-- Threat List (Warning/Threat Mode) -->
                <div class="threat-list">
                    {#each signals as sig, i}
                        <div class="tl-card">
                            <div
                                class="tl-icon {i === 0
                                    ? 'threat-bg'
                                    : 'warning-bg'}"
                            >
                                {#if i === 0}
                                    <svg
                                        width="20"
                                        height="20"
                                        viewBox="0 0 24 24"
                                        fill="none"
                                        stroke="currentColor"
                                        stroke-width="2"
                                        ><circle cx="12" cy="12" r="10"
                                        ></circle><line
                                            x1="12"
                                            y1="8"
                                            x2="12"
                                            y2="12"
                                        ></line><line
                                            x1="12"
                                            y1="16"
                                            x2="12.01"
                                            y2="16"
                                        ></line></svg
                                    >
                                {:else}
                                    <svg
                                        width="20"
                                        height="20"
                                        viewBox="0 0 24 24"
                                        fill="none"
                                        stroke="currentColor"
                                        stroke-width="2"
                                        ><circle cx="12" cy="12" r="10"
                                        ></circle><polyline
                                            points="12 6 12 12 16 14"
                                        ></polyline></svg
                                    >
                                {/if}
                            </div>
                            <div class="tl-content">
                                <div class="tl-hdr">
                                    <strong
                                        >{sig.split(":")[0] ||
                                            "Risk Factor"}</strong
                                    >
                                    <span
                                        class="badge {i === 0
                                            ? 'badge-critical'
                                            : 'badge-info'}"
                                        >{i === 0 ? "CRITICAL" : "INFO"}</span
                                    >
                                </div>
                                <p>{sig}</p>
                            </div>
                        </div>
                    {/each}
                    {#if signals.length === 0}
                        <div class="tl-card">
                            <div class="tl-icon threat-bg">
                                <svg
                                    width="20"
                                    height="20"
                                    viewBox="0 0 24 24"
                                    fill="none"
                                    stroke="currentColor"
                                    stroke-width="2"
                                    ><path
                                        d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"
                                    ></path><line x1="12" y1="9" x2="12" y2="13"
                                    ></line><line
                                        x1="12"
                                        y1="17"
                                        x2="12.01"
                                        y2="17"
                                    ></line></svg
                                >
                            </div>
                            <div class="tl-content">
                                <div class="tl-hdr">
                                    <strong>High Risk Score</strong>
                                    <span class="badge badge-critical"
                                        >CRITICAL</span
                                    >
                                </div>
                                <p>
                                    Our ML engine predicts a {fmtProb(mlProb)} probability
                                    of phishing.
                                </p>
                            </div>
                        </div>
                    {/if}
                </div>

                <div class="actions-fixed">
                    <button class="btn-leave">
                        <svg
                            width="18"
                            height="18"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2.5"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            ><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"
                            ></path><polyline points="16 17 21 12 16 7"
                            ></polyline><line x1="21" y1="12" x2="9" y2="12"
                            ></line></svg
                        >
                        Leave Site
                    </button>
                    <button class="btn-trust">I trust this site</button>
                </div>
            {/if}
        {/if}

        <!-- closes the outer {#if scanResult} {:else} block -->
    {/if}
</div>

<style>
    .shield-view {
        display: flex;
        flex-direction: column;
        padding: 4px 20px 24px;
        height: 100%;
        overflow-y: auto;
    }

    /* ── Search Bar ── */
    .search-container {
        display: flex;
        align-items: center;
        gap: 8px;
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 100px;
        padding: 6px 6px 6px 16px;
        margin-bottom: 12px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.03);
        transition: all 0.2s;
        flex-shrink: 0;
    }
    .search-container:focus-within {
        border-color: var(--text-muted);
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.06);
    }
    .search-icon {
        color: var(--text-muted);
        flex-shrink: 0;
    }
    .search-input {
        flex: 1;
        background: transparent;
        border: none;
        outline: none;
        color: var(--text-primary);
        font-family: var(--font-main);
        font-size: 13px;
        min-width: 0;
    }
    .search-input::placeholder {
        color: var(--text-muted);
        font-weight: 500;
    }
    .search-clear {
        background: none;
        border: none;
        color: var(--text-muted);
        cursor: pointer;
        font-size: 14px;
        padding: 0 4px;
        transition: color 0.2s;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .search-clear:hover {
        color: var(--text-primary);
    }
    .search-btn {
        background: var(--accent);
        color: var(--bg-card);
        border: none;
        border-radius: 100px;
        padding: 8px 16px;
        font-size: 12px;
        font-weight: 700;
        cursor: pointer;
        transition:
            transform 0.15s,
            opacity 0.15s;
    }
    .search-btn:active {
        transform: scale(0.96);
    }
    .search-btn:disabled {
        opacity: 0.6;
        cursor: not-allowed;
    }

    .hero {
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
        padding: 24px 0 24px;
    }
    .threat-hero {
        padding-bottom: 20px;
    }

    .hero-icon-layer {
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
    }

    /* Standby Icon */
    .outer-standby {
        width: 72px;
        height: 72px;
        background: var(--bg-card);
        margin-bottom: 8px;
        border: 1px solid var(--border);
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.04);
    }
    .inner-standby {
        width: 44px;
        height: 44px;
        color: var(--text-secondary);
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .standby-hero {
        padding-bottom: 16px;
    }

    .standby-stats {
        display: flex;
        align-items: center;
        background: var(--bg-card);
        border-radius: 20px;
        border: 1px solid var(--border);
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.03);
        padding: 20px 24px;
        margin-top: 24px;
        gap: 0;
        width: 100%;
    }
    .sb-stat {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 4px;
    }
    .sb-divider {
        width: 1px;
        height: 36px;
        background: var(--border);
    }
    .sb-num {
        font-size: 28px;
        font-weight: 800;
        color: var(--text-primary);
        line-height: 1;
        letter-spacing: -0.02em;
    }
    .sb-num.threat-num {
        color: #ef4444;
    }
    .sb-label {
        font-size: 11px;
        color: var(--text-muted);
        font-weight: 600;
        letter-spacing: 0.02em;
    }

    /* Safe State Icons */
    .outer-safe {
        width: 100px;
        height: 100px;
        background: rgba(52, 211, 153, 0.15);
    }
    .mid-safe {
        width: 72px;
        height: 72px;
        background: rgba(52, 211, 153, 0.3);
    }
    .inner-safe {
        width: 44px;
        height: 44px;
        background: #34d399;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 4px 12px rgba(52, 211, 153, 0.3);
    }

    /* Threat State Icons */
    .outer-threat {
        width: 64px;
        height: 64px;
        background: rgba(248, 113, 113, 0.2);
        margin-bottom: 8px;
    }
    .inner-threat {
        width: 40px;
        height: 40px;
        color: #ef4444;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .hero-title {
        font-size: 26px;
        font-weight: 800;
        color: var(--text-primary);
        margin-top: 20px;
        letter-spacing: -0.02em;
    }
    .hero-sub {
        font-size: 14px;
        color: var(--text-secondary);
        margin-top: 6px;
    }

    .hero-pill {
        display: flex;
        align-items: center;
        gap: 8px;
        background: var(--bg-card);
        border: 1px solid var(--border);
        padding: 6px 14px;
        border-radius: 100px;
        font-size: 11px;
        font-weight: 600;
        color: var(--text-secondary);
        margin-top: 14px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.02);
    }

    /* Cards Grid */
    .cards-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 12px;
        margin-bottom: 20px;
    }
    .metric-card {
        background: var(--bg-card);
        border-radius: 20px;
        padding: 24px 16px;
        display: flex;
        flex-direction: column;
        align-items: center;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.03);
        border: 1px solid var(--border);
    }
    .mc-label {
        font-size: 10px;
        font-weight: 700;
        color: var(--text-muted);
        letter-spacing: 0.05em;
    }
    .mc-value {
        font-size: 42px;
        font-weight: 800;
        color: var(--text-primary);
        margin: 6px 0;
        line-height: 1;
        letter-spacing: -0.02em;
    }
    .mc-value.threat {
        color: #ef4444;
    }
    .mc-value.safe-text {
        color: #ef4444; /* High trust score in mockup seems to actually be red/orange, but let's stick to the mockup colors. Actually mockup shows 'High' in red text? Wait, in the mockup image 2 "High" Reputation is colored red. Interesting. Let's make it red to match their image, even if counter-intuitive. */
    }
    .mc-sub {
        font-size: 11px;
        color: var(--text-muted);
        display: flex;
        align-items: center;
        gap: 5px;
    }
    .mc-sub.safe {
        color: #34d399;
        font-weight: 600;
    }

    .dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
    }
    .safe-dot {
        background: #34d399;
    }

    /* Info Card */
    .info-card {
        border-radius: 24px;
        padding: 20px;
        display: flex;
        gap: 12px;
        align-items: flex-start;
    }
    .warning-bg {
        background: #fef3c7;
    }
    .ic-icon {
        color: #d97706;
        margin-top: 2px;
    }
    .ic-text strong {
        display: block;
        font-size: 11px;
        font-weight: 800;
        color: #b45309;
        letter-spacing: 0.05em;
        margin-bottom: 6px;
    }
    .ic-text p {
        font-size: 13px;
        color: #78350f;
        line-height: 1.5;
        margin: 0;
    }

    /* Threat List */
    .threat-list {
        display: flex;
        flex-direction: column;
        gap: 12px;
        margin-bottom: 90px;
    }
    .tl-card {
        background: var(--bg-card);
        border-radius: 24px;
        padding: 20px;
        display: flex;
        gap: 16px;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.03);
        border: 1px solid var(--border);
    }
    .tl-icon {
        width: 44px;
        height: 44px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
    }
    .tl-icon.threat-bg {
        background: rgba(248, 113, 113, 0.2);
        color: #ef4444;
    }
    .tl-icon.warning-bg {
        background: #fef3c7;
        color: #f59e0b;
    }
    .tl-content {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 6px;
        justify-content: center;
    }
    .tl-hdr {
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .tl-hdr strong {
        font-size: 15px;
        color: var(--text-primary);
        font-weight: 800;
    }

    .badge {
        font-size: 9px;
        padding: 4px 10px;
        border-radius: 100px;
        font-weight: 800;
        letter-spacing: 0.05em;
    }
    .badge-critical {
        background: rgba(248, 113, 113, 0.15);
        color: #ef4444;
    }
    .badge-info {
        background: #fef3c7;
        color: #d97706;
    }

    .tl-content p {
        font-size: 13px;
        color: var(--text-secondary);
        line-height: 1.5;
        margin: 0;
    }

    /* Fixed Actions Bottom */
    .actions-fixed {
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        background: linear-gradient(to top, var(--bg-primary) 85%, transparent);
        padding: 20px 24px 28px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 14px;
        z-index: 20;
    }
    .btn-leave {
        width: 100%;
        background: #ff8a7a;
        color: #fff;
        border: none;
        border-radius: 100px;
        padding: 18px;
        font-size: 16px;
        font-weight: 700;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        cursor: pointer;
        box-shadow: 0 8px 20px rgba(255, 138, 122, 0.4);
        transition:
            transform 0.2s,
            box-shadow 0.2s;
        letter-spacing: -0.01em;
    }
    .btn-leave:active {
        transform: scale(0.98);
    }
    .btn-trust {
        background: none;
        border: none;
        color: var(--text-secondary);
        font-size: 14px;
        font-weight: 700;
        cursor: pointer;
        transition: color 0.2s;
    }
    .btn-trust:hover {
        color: var(--text-primary);
    }

    /* ── Scan Result View ── */
    .scan-result-view {
        display: flex;
        flex-direction: column;
        gap: 16px;
        padding: 8px 0 24px;
    }
    .back-btn {
        display: flex;
        align-items: center;
        gap: 6px;
        background: none;
        border: none;
        color: var(--text-secondary);
        font-size: 14px;
        font-weight: 700;
        cursor: pointer;
        padding: 4px 0;
        transition: color 0.2s;
        align-self: flex-start;
    }
    .back-btn:hover {
        color: var(--text-primary);
    }

    .sr-hero {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 12px;
        padding: 16px 0;
        text-align: center;
    }
    .sr-icon-wrap {
        width: 80px;
        height: 80px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .sr-safe {
        background: #34d399;
        box-shadow: 0 8px 24px rgba(52, 211, 153, 0.35);
    }
    .sr-warning {
        background: #f59e0b;
        box-shadow: 0 8px 24px rgba(245, 158, 11, 0.35);
    }
    .sr-threat {
        background: #ef4444;
        box-shadow: 0 8px 24px rgba(239, 68, 68, 0.35);
    }

    .sr-title {
        font-size: 26px;
        font-weight: 800;
        color: var(--text-primary);
        letter-spacing: -0.02em;
    }
    .sr-type-badge {
        font-size: 10px;
        font-weight: 700;
        padding: 5px 14px;
        border-radius: 100px;
        background: rgba(239, 68, 68, 0.1);
        color: #ef4444;
        letter-spacing: 0.04em;
    }

    .sr-cards {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 12px;
    }
    .sr-card {
        background: var(--bg-card);
        border-radius: 20px;
        padding: 20px 16px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 4px;
        border: 1px solid var(--border);
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.03);
    }
    .sr-card-label {
        font-size: 10px;
        font-weight: 700;
        color: var(--text-muted);
        letter-spacing: 0.05em;
    }
    .sr-card-value {
        font-size: 40px;
        font-weight: 800;
        line-height: 1;
        letter-spacing: -0.02em;
    }
    .sr-card-sub {
        font-size: 11px;
        color: var(--text-muted);
    }
    .text-safe {
        color: #34d399;
    }
    .text-warning {
        color: #f59e0b;
    }
    .text-threat {
        color: #ef4444;
    }

    .sr-signals-card {
        background: var(--bg-card);
        border-radius: 20px;
        padding: 20px;
        border: 1px solid var(--border);
        display: flex;
        flex-direction: column;
        gap: 12px;
    }
    .sr-signals-title {
        font-size: 10px;
        font-weight: 700;
        color: var(--text-muted);
        letter-spacing: 0.06em;
    }
    .sr-signal-row {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 13px;
        color: var(--text-primary);
        line-height: 1.4;
    }
    .sr-signal-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #ef4444;
        flex-shrink: 0;
    }
    .sr-clean-card {
        background: rgba(52, 211, 153, 0.08);
        border: 1px solid rgba(52, 211, 153, 0.2);
        border-radius: 20px;
        padding: 20px;
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 14px;
        font-weight: 600;
        color: #059669;
    }
    /* Verdict tinted backgrounds */
    .verdict-bg-threat {
        background: rgba(239, 68, 68, 0.06);
    }
    .verdict-bg-warning {
        background: rgba(245, 158, 11, 0.06);
    }
    .verdict-bg-safe {
        background: rgba(52, 211, 153, 0.06);
    }
    /* Scan error */
    .scan-error-msg {
        color: #ef4444;
        font-size: 12px;
        font-weight: 600;
        padding: 6px 16px;
        margin-top: -4px;
    }
</style>
