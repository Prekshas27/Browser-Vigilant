<script>
    /**
     * Settings.svelte — Persisted settings via chrome.storage.sync
     * Changes flow up to App.svelte which calls background.js.
     */
    export let settings = null;
    export let onChange = (_) => {};

    // Defaults (used if settings prop is null, e.g. dev mode)
    let local = {
        protection: true,
        autoBlock: true,
        blockThreshold: 0.5,
        upiDetection: true,
        downloadScanner: true,
        domAnalysis: true,
        notifications: true,
        strictMode: false,
    };

    $: if (settings) {
        local = Object.assign({}, local, settings);
    }

    function update(key, value) {
        local = { ...local, [key]: value };
        onChange({ ...local });
    }

    const thresholds = [
        { value: 0.35, label: "Very Low (35%)" },
        { value: 0.5, label: "Standard (50%)" },
        { value: 0.65, label: "High (65%)" },
        { value: 0.8, label: "Strict (80%)" },
    ];
</script>

<div class="settings-wrap">
    <!-- Protection group -->
    <div class="settings-group">
        <div class="group-label">Protection</div>

        <div class="setting-row">
            <div class="setting-info">
                <span class="setting-name">Real-Time Shield</span>
                <span class="setting-desc"
                    >Scan every page with AI+WASM engine</span
                >
            </div>
            <label class="toggle">
                <input
                    type="checkbox"
                    checked={local.protection}
                    on:change={(e) =>
                        update(
                            "protection",
                            /** @type {HTMLInputElement} */ (e.target).checked,
                        )}
                />
                <span class="toggle-track"></span>
            </label>
        </div>

        <div class="setting-row">
            <div class="setting-info">
                <span class="setting-name">Auto-Block Threats</span>
                <span class="setting-desc"
                    >Replace threat pages with block screen</span
                >
            </div>
            <label class="toggle">
                <input
                    type="checkbox"
                    checked={local.autoBlock}
                    on:change={(e) =>
                        update(
                            "autoBlock",
                            /** @type {HTMLInputElement} */ (e.target).checked,
                        )}
                />
                <span class="toggle-track"></span>
            </label>
        </div>

        <div class="setting-row">
            <div class="setting-info">
                <span class="setting-name">Strict Mode</span>
                <span class="setting-desc"
                    >Lower threshold — flag borderline sites</span
                >
            </div>
            <label class="toggle">
                <input
                    type="checkbox"
                    checked={local.strictMode}
                    on:change={(e) =>
                        update(
                            "strictMode",
                            /** @type {HTMLInputElement} */ (e.target).checked,
                        )}
                />
                <span class="toggle-track"></span>
            </label>
        </div>

        <div class="setting-row last">
            <div class="setting-info">
                <span class="setting-name">ML Block Threshold</span>
                <span class="setting-desc"
                    >Minimum ML probability to trigger a block</span
                >
            </div>
            <select
                class="select-input"
                value={local.blockThreshold}
                on:change={(e) =>
                    update(
                        "blockThreshold",
                        parseFloat(
                            /** @type {HTMLSelectElement} */ (e.target).value,
                        ),
                    )}
            >
                {#each thresholds as t}
                    <option value={t.value}>{t.label}</option>
                {/each}
            </select>
        </div>
    </div>

    <!-- Detection layers -->
    <div class="settings-group">
        <div class="group-label">Detection Layers</div>

        <div class="setting-row">
            <div class="setting-info">
                <span class="setting-name">UPI Fraud Detection</span>
                <span class="setting-desc"
                    >Scan DOM for fraudulent VPA addresses</span
                >
            </div>
            <label class="toggle">
                <input
                    type="checkbox"
                    checked={local.upiDetection}
                    on:change={(e) =>
                        update(
                            "upiDetection",
                            /** @type {HTMLInputElement} */ (e.target).checked,
                        )}
                />
                <span class="toggle-track"></span>
            </label>
        </div>

        <div class="setting-row">
            <div class="setting-info">
                <span class="setting-name">Download Scanner</span>
                <span class="setting-desc">Block malicious file downloads</span>
            </div>
            <label class="toggle">
                <input
                    type="checkbox"
                    checked={local.downloadScanner}
                    on:change={(e) =>
                        update(
                            "downloadScanner",
                            /** @type {HTMLInputElement} */ (e.target).checked,
                        )}
                />
                <span class="toggle-track"></span>
            </label>
        </div>

        <div class="setting-row last">
            <div class="setting-info">
                <span class="setting-name">DOM Analysis</span>
                <span class="setting-desc"
                    >Detect credential harvesting in page DOM</span
                >
            </div>
            <label class="toggle">
                <input
                    type="checkbox"
                    checked={local.domAnalysis}
                    on:change={(e) =>
                        update(
                            "domAnalysis",
                            /** @type {HTMLInputElement} */ (e.target).checked,
                        )}
                />
                <span class="toggle-track"></span>
            </label>
        </div>
    </div>

    <!-- Alerts -->
    <div class="settings-group">
        <div class="group-label">Alerts</div>
        <div class="setting-row last">
            <div class="setting-info">
                <span class="setting-name">Block Notifications</span>
                <span class="setting-desc"
                    >Desktop notification on each blocked threat</span
                >
            </div>
            <label class="toggle">
                <input
                    type="checkbox"
                    checked={local.notifications}
                    on:change={(e) =>
                        update(
                            "notifications",
                            /** @type {HTMLInputElement} */ (e.target).checked,
                        )}
                />
                <span class="toggle-track"></span>
            </label>
        </div>
    </div>

    <!-- About -->
    <div class="settings-group about-group">
        <div class="group-label">About</div>
        <div class="about-grid">
            {#each [["Version", "2.0.0"], ["ML Model", "RF×300 + GBM×200 Ensemble"], ["Features", "48 (Rust WASM)"], ["Blockchain", "SHA-256 Local Ledger"], ["Privacy", "100% On-Device"], ["Data Shared", "None"]] as [k, v]}
                <div class="about-row">
                    <span class="about-key">{k}</span>
                    <span
                        class="about-val"
                        style={k === "Privacy" || k === "Data Shared"
                            ? "color:var(--accent-green)"
                            : ""}
                    >
                        {v}
                    </span>
                </div>
            {/each}
        </div>
    </div>
</div>

<style>
    .settings-wrap {
        display: flex;
        flex-direction: column;
        gap: 12px;
    }

    .settings-group {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        overflow: hidden;
    }
    .group-label {
        font-size: 8.5px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: var(--text-muted);
        padding: 8px 13px 6px;
        border-bottom: 1px solid var(--border);
    }

    .setting-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 13px;
        border-bottom: 1px solid var(--border);
        gap: 10px;
        transition: background 0.12s;
    }
    .setting-row:hover {
        background: var(--bg-card-hover);
    }
    .setting-row.last {
        border-bottom: none;
    }

    .setting-info {
        display: flex;
        flex-direction: column;
        gap: 2px;
        flex: 1;
    }
    .setting-name {
        font-size: 12px;
        font-weight: 500;
        color: var(--text-primary);
    }
    .setting-desc {
        font-size: 9px;
        color: var(--text-muted);
        font-family: var(--font-mono);
    }

    /* Toggle */
    .toggle {
        position: relative;
        cursor: pointer;
        flex-shrink: 0;
    }
    .toggle input {
        display: none;
    }
    .toggle-track {
        display: block;
        width: 34px;
        height: 18px;
        background: rgba(255, 255, 255, 0.07);
        border-radius: 100px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        position: relative;
        transition: all 0.2s;
    }
    .toggle-track::after {
        content: "";
        position: absolute;
        top: 2px;
        left: 2px;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background: var(--text-muted);
        transition: all 0.2s;
    }
    .toggle input:checked + .toggle-track {
        background: rgba(59, 130, 246, 0.25);
        border-color: var(--accent);
    }
    .toggle input:checked + .toggle-track::after {
        transform: translateX(16px);
        background: var(--accent);
        box-shadow: 0 0 6px var(--accent);
    }

    /* Select */
    .select-input {
        background: var(--bg-secondary);
        border: 1px solid var(--border);
        color: var(--text-secondary);
        font-family: var(--font-mono);
        font-size: 9px;
        padding: 4px 8px;
        border-radius: 6px;
        cursor: pointer;
        outline: none;
        transition: border-color 0.15s;
        flex-shrink: 0;
        max-width: 130px;
    }
    .select-input:focus {
        border-color: var(--accent);
    }

    /* About */
    .about-group .group-label {
        border-bottom: none;
    }
    .about-grid {
        padding: 0;
    }
    .about-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 7px 13px;
        border-bottom: 1px solid var(--border);
    }
    .about-row:last-child {
        border-bottom: none;
    }
    .about-key {
        font-size: 10px;
        color: var(--text-muted);
    }
    .about-val {
        font-size: 10px;
        font-family: var(--font-mono);
        color: var(--text-secondary);
        text-align: right;
    }
</style>
