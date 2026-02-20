<script>
    /**
     * ThreatMap.svelte — Live SHA-256 Blockchain Threat Ledger
     * Reads chain from chrome.storage (via App.svelte props).
     * Performs local integrity verification on render.
     */
    export let chain = [];
    export let chainTampered = false;

    function shortHash(h) {
        if (!h || h.length < 12) return h || "—";
        return h.slice(0, 8) + "…" + h.slice(-6);
    }

    function fmtTime(ts) {
        if (!ts) return "—";
        try {
            return new Date(ts).toLocaleTimeString("en-IN", {
                hour: "2-digit",
                minute: "2-digit",
            });
        } catch {
            return ts;
        }
    }

    function fmtDate(ts) {
        if (!ts) return "";
        try {
            const d = new Date(ts);
            const today = new Date();
            if (d.toDateString() === today.toDateString()) return "Today";
            return d.toLocaleDateString("en-IN", {
                month: "short",
                day: "numeric",
            });
        } catch {
            return "";
        }
    }

    function threatColor(type) {
        if (!type) return "var(--accent)";
        const t = type.toLowerCase();
        if (t.includes("upi")) return "#a78bfa";
        if (t.includes("mal")) return "#f97316";
        if (t.includes("dom")) return "#f59e0b";
        if (t.includes("idn") || t.includes("homograph")) return "#ec4899";
        return "#ef4444";
    }

    $: genesisBlock = chain.find((b) => b.type === "GENESIS");
    $: threatBlocks = chain.filter((b) => b.type === "THREAT_BLOCKED");
    $: chainLen = chain.length;
    $: chainIntact = !chainTampered;

    // Group blocks by date for display
    $: grouped = (() => {
        const groups = [];
        let lastDate = null;
        for (const block of [...chain].reverse()) {
            const d = fmtDate(block.timestamp);
            if (d !== lastDate) {
                groups.push({ date: d, blocks: [] });
                lastDate = d;
            }
            groups[groups.length - 1].blocks.push(block);
        }
        return groups;
    })();
</script>

<div class="chain-wrap">
    <!-- Integrity banner -->
    <div class="integrity-banner {chainIntact ? 'valid' : 'invalid'}">
        <div class="int-icon">{chainIntact ? "🔒" : "⚠️"}</div>
        <div class="int-info">
            <span class="int-title">
                {chainIntact
                    ? "Ledger Integrity Verified"
                    : "⚠ LEDGER TAMPERED"}
            </span>
            <span class="int-sub"
                >{chainLen} blocks · SHA-256 chained · {threatBlocks.length} threats</span
            >
        </div>
        <span class="int-badge {chainIntact ? 'ok' : 'bad'}"
            >{chainIntact ? "INTACT" : "BROKEN"}</span
        >
    </div>

    <!-- Stats -->
    <div class="chain-stats">
        <div class="cs-item">
            <span class="cs-num accent-blue">{chainLen}</span>
            <span class="cs-lbl">Blocks</span>
        </div>
        <div class="cs-item">
            <span class="cs-num accent-red">{threatBlocks.length}</span>
            <span class="cs-lbl">Threats</span>
        </div>
        <div class="cs-item">
            <span class="cs-num {chainIntact ? 'accent-green' : 'accent-red'}"
                >{chainIntact ? "100%" : "0%"}</span
            >
            <span class="cs-lbl">Integrity</span>
        </div>
        <div class="cs-item">
            <span class="cs-num accent-purple">SHA-256</span>
            <span class="cs-lbl">Hash Fn</span>
        </div>
    </div>

    <!-- Explainer -->
    <div class="explainer">
        <span class="expl-icon">⛓️</span>
        <span class="expl-text">
            Every blocked threat is hashed with <strong>SHA-256</strong> and cryptographically
            chained. No block can be silently deleted or altered without detection.
        </span>
    </div>

    <!-- Block list -->
    {#if chain.length === 0}
        <div class="empty-state">
            <span class="empty-icon">📭</span>
            <p class="empty-txt">No threats in ledger yet.</p>
        </div>
    {:else}
        <div class="block-list">
            {#each grouped as group}
                <div class="date-group">
                    <div class="date-label">{group.date}</div>
                    {#each group.blocks as block}
                        <div
                            class="chain-block {block.type === 'GENESIS'
                                ? 'genesis'
                                : 'threat'}"
                        >
                            {#if block.type !== "GENESIS"}
                                <div class="connector">
                                    <div class="conn-line"></div>
                                </div>
                            {/if}

                            <div class="block-inner">
                                <!-- Block header -->
                                <div class="block-hdr">
                                    <span class="block-idx">#{block.index}</span
                                    >
                                    <span
                                        class="block-type-badge {block.type ===
                                        'GENESIS'
                                            ? 'gen-badge'
                                            : 'thr-badge'}"
                                    >
                                        {block.type === "GENESIS"
                                            ? "Genesis"
                                            : "Threat"}
                                    </span>
                                    {#if block.threatType}
                                        <span
                                            class="block-threat-type"
                                            style="color:{threatColor(
                                                block.threatType,
                                            )}"
                                        >
                                            {block.threatType}
                                        </span>
                                    {/if}
                                    <span class="block-time"
                                        >{fmtTime(block.timestamp)}</span
                                    >
                                </div>

                                <!-- URL -->
                                {#if block.url}
                                    <div class="block-url">
                                        {block.url.length > 44
                                            ? block.url.slice(0, 41) + "…"
                                            : block.url}
                                    </div>
                                {:else}
                                    <div class="block-url genesis-url">
                                        Browser Vigilant · Ledger Initialized
                                    </div>
                                {/if}

                                <!-- Signals -->
                                {#if block.signals && block.signals.length > 0}
                                    <div class="block-signals">
                                        {#each block.signals.slice(0, 3) as sig}
                                            <span class="sig-chip">{sig}</span>
                                        {/each}
                                    </div>
                                {/if}

                                <!-- Risk + Hashes -->
                                <div class="block-footer">
                                    {#if block.riskScore !== null && block.riskScore !== undefined}
                                        <span class="risk-tag"
                                            >Risk {block.riskScore}/100</span
                                        >
                                    {/if}
                                    <div class="hashes">
                                        <div class="hash-row">
                                            <span class="hash-key">PREV</span>
                                            <span class="hash-val"
                                                >{shortHash(
                                                    block.prevHash,
                                                )}</span
                                            >
                                        </div>
                                        <div class="hash-row">
                                            <span class="hash-key">HASH</span>
                                            <span class="hash-val accent"
                                                >{shortHash(block.hash)}</span
                                            >
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    {/each}
                </div>
            {/each}
        </div>
    {/if}
</div>

<style>
    .chain-wrap {
        display: flex;
        flex-direction: column;
        gap: 10px;
    }

    .integrity-banner {
        display: flex;
        align-items: center;
        gap: 9px;
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid;
    }
    .integrity-banner.valid {
        border-color: rgba(16, 185, 129, 0.3);
        background: rgba(16, 185, 129, 0.06);
    }
    .integrity-banner.invalid {
        border-color: rgba(239, 68, 68, 0.3);
        background: rgba(239, 68, 68, 0.06);
    }
    .int-icon {
        font-size: 18px;
    }
    .int-info {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .int-title {
        font-size: 11px;
        font-weight: 700;
        color: var(--text-primary);
    }
    .int-sub {
        font-size: 8.5px;
        color: var(--text-muted);
        font-family: var(--font-mono);
    }
    .int-badge {
        font-size: 8px;
        font-weight: 800;
        letter-spacing: 0.1em;
        padding: 2px 8px;
        border-radius: 100px;
    }
    .int-badge.ok {
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.4);
        background: rgba(16, 185, 129, 0.1);
    }
    .int-badge.bad {
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.4);
        background: rgba(239, 68, 68, 0.1);
    }

    .chain-stats {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 7px;
    }
    .cs-item {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 8px 4px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 2px;
    }
    .cs-num {
        font-size: 13px;
        font-weight: 700;
        font-family: var(--font-mono);
    }
    .accent-blue {
        color: var(--accent);
    }
    .accent-red {
        color: var(--accent-red);
    }
    .accent-green {
        color: var(--accent-green);
    }
    .accent-purple {
        color: #a78bfa;
    }
    .cs-lbl {
        font-size: 8px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .explainer {
        display: flex;
        align-items: flex-start;
        gap: 7px;
        padding: 8px 11px;
        background: rgba(59, 130, 246, 0.05);
        border: 1px solid rgba(59, 130, 246, 0.14);
        border-radius: 8px;
        font-size: 9.5px;
        color: var(--text-secondary);
        line-height: 1.55;
    }
    .expl-icon {
        font-size: 13px;
        flex-shrink: 0;
    }
    .explainer strong {
        color: var(--accent);
    }

    .empty-state {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 8px;
        padding: 28px 0;
    }
    .empty-icon {
        font-size: 26px;
        opacity: 0.4;
    }
    .empty-txt {
        font-size: 11px;
        color: var(--text-muted);
        font-family: var(--font-mono);
    }

    .block-list {
        display: flex;
        flex-direction: column;
        gap: 0;
    }
    .date-group {
        display: flex;
        flex-direction: column;
        gap: 0;
    }
    .date-label {
        font-size: 9px;
        color: var(--text-muted);
        font-family: var(--font-mono);
        letter-spacing: 0.06em;
        text-transform: uppercase;
        padding: 6px 2px 4px;
        font-weight: 600;
    }

    .chain-block {
        display: flex;
        flex-direction: column;
    }
    .connector {
        display: flex;
        justify-content: flex-start;
        padding-left: 14px;
    }
    .conn-line {
        width: 1px;
        height: 10px;
        background: var(--border-glow);
    }

    .block-inner {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        overflow: hidden;
        transition: border-color 0.18s;
        margin-bottom: 0;
    }
    .block-inner:hover {
        border-color: var(--border-glow);
    }
    .chain-block.threat .block-inner {
        border-color: rgba(239, 68, 68, 0.18);
    }
    .chain-block.genesis .block-inner {
        border-color: rgba(59, 130, 246, 0.18);
    }

    .block-hdr {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 7px 10px 5px;
        border-bottom: 1px solid var(--border);
    }
    .block-idx {
        font-size: 9px;
        font-family: var(--font-mono);
        color: var(--text-muted);
        font-weight: 700;
    }
    .block-type-badge {
        font-size: 8.5px;
        font-weight: 700;
        padding: 1px 7px;
        border-radius: 100px;
        letter-spacing: 0.04em;
    }
    .gen-badge {
        background: rgba(59, 130, 246, 0.1);
        border: 1px solid rgba(59, 130, 246, 0.25);
        color: var(--accent);
    }
    .thr-badge {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.25);
        color: var(--accent-red);
    }
    .block-threat-type {
        font-size: 9px;
        font-family: var(--font-mono);
        flex: 1;
    }
    .block-time {
        font-size: 8.5px;
        color: var(--text-muted);
        font-family: var(--font-mono);
        margin-left: auto;
    }

    .block-url {
        padding: 5px 10px;
        font-size: 9.5px;
        font-family: var(--font-mono);
        color: var(--text-secondary);
        border-bottom: 1px solid var(--border);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    .genesis-url {
        color: var(--text-muted);
        font-style: italic;
    }

    .block-signals {
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
        padding: 5px 10px;
        border-bottom: 1px solid var(--border);
    }
    .sig-chip {
        font-size: 8.5px;
        padding: 1px 7px;
        border-radius: 100px;
        background: rgba(239, 68, 68, 0.07);
        border: 1px solid rgba(239, 68, 68, 0.18);
        color: var(--accent-red);
        font-family: var(--font-mono);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 140px;
    }

    .block-footer {
        display: flex;
        align-items: flex-end;
        justify-content: space-between;
        padding: 6px 10px;
        gap: 8px;
    }
    .risk-tag {
        font-size: 8.5px;
        padding: 1px 7px;
        border-radius: 100px;
        background: rgba(239, 68, 68, 0.08);
        border: 1px solid rgba(239, 68, 68, 0.2);
        color: var(--accent-red);
        font-family: var(--font-mono);
        white-space: nowrap;
        flex-shrink: 0;
    }
    .hashes {
        display: flex;
        flex-direction: column;
        gap: 2px;
        align-items: flex-end;
    }
    .hash-row {
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .hash-key {
        font-size: 7.5px;
        font-weight: 800;
        letter-spacing: 0.1em;
        color: var(--text-muted);
        width: 26px;
    }
    .hash-val {
        font-size: 8.5px;
        font-family: var(--font-mono);
        color: var(--text-secondary);
    }
    .hash-val.accent {
        color: var(--accent);
    }
</style>
