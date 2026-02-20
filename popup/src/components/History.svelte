<script>
    /**
     * History.svelte — Real scan log from chrome.storage.local
     * No hardcoded data. Reads from props passed by App.svelte.
     */
    export let history = [];
    export let onClear = () => {};

    let filter = "all"; // "all" | "blocked" | "safe" | "warning"
    let confirmClear = false;

    $: filtered = history.filter((h) => {
        if (filter === "all") return true;
        if (filter === "blocked") return h.status === "threat";
        if (filter === "safe") return h.status === "safe";
        if (filter === "warning") return h.status === "warning";
        return true;
    });

    $: totalBlocked = history.filter((h) => h.status === "threat").length;
    $: totalSafe = history.filter((h) => h.status === "safe").length;
    $: avgMs = history.length
        ? (
              history.reduce((s, h) => s + (h.scanMs || 0), 0) / history.length
          ).toFixed(1)
        : "—";

    function fmtUrl(url) {
        if (!url) return "—";
        try {
            url = decodeURIComponent(url);
        } catch {}
        return url.length > 40 ? url.slice(0, 37) + "…" : url;
    }

    function fmtTime(ts) {
        if (!ts) return "—";
        try {
            return new Date(ts).toLocaleTimeString("en-IN", {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
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
            const yest = new Date(today);
            yest.setDate(today.getDate() - 1);
            if (d.toDateString() === yest.toDateString()) return "Yesterday";
            return d.toLocaleDateString("en-IN", {
                month: "short",
                day: "numeric",
            });
        } catch {
            return "";
        }
    }

    function statusColor(status) {
        if (status === "threat") return "#ef4444";
        if (status === "warning") return "#f59e0b";
        return "#10b981";
    }

    function statusLabel(status) {
        if (status === "threat") return "Blocked";
        if (status === "warning") return "Warning";
        return "Safe";
    }

    function exportHistory() {
        const blob = new Blob([JSON.stringify(history, null, 2)], {
            type: "application/json",
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `bv-history-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    function handleClear() {
        if (!confirmClear) {
            confirmClear = true;
            return;
        }
        onClear();
        confirmClear = false;
    }
</script>

<div class="history-wrap">
    <!-- Summary cards -->
    <div class="summary-row">
        <div class="sum-card safe">
            <span class="sum-num">{totalSafe}</span>
            <span class="sum-label">Safe</span>
        </div>
        <div class="sum-card blocked">
            <span class="sum-num">{totalBlocked}</span>
            <span class="sum-label">Blocked</span>
        </div>
        <div class="sum-card">
            <span class="sum-num">{avgMs}ms</span>
            <span class="sum-label">Avg Scan</span>
        </div>
        <div class="sum-card">
            <span class="sum-num">{history.length}</span>
            <span class="sum-label">Total</span>
        </div>
    </div>

    <!-- Filters + actions -->
    <div class="toolbar">
        <div class="filters">
            {#each ["all", "safe", "warning", "blocked"] as f}
                <button
                    class="filter-btn {filter === f ? 'active' : ''}"
                    on:click={() => {
                        filter = f;
                        confirmClear = false;
                    }}>{f.charAt(0).toUpperCase() + f.slice(1)}</button
                >
            {/each}
        </div>
        <div class="actions">
            <button
                class="action-btn"
                on:click={exportHistory}
                title="Export JSON">⬇ Export</button
            >
            <button
                class="action-btn {confirmClear ? 'danger' : ''}"
                on:click={handleClear}
                on:blur={() => (confirmClear = false)}
                title="Clear history"
                >{confirmClear ? "Confirm?" : "🗑 Clear"}</button
            >
        </div>
    </div>

    <!-- Scan list -->
    {#if filtered.length === 0}
        <div class="empty-state">
            <span class="empty-icon">📭</span>
            <p class="empty-txt">
                {history.length === 0
                    ? "No scans yet. Browse to a page to start."
                    : "No entries match this filter."}
            </p>
        </div>
    {:else}
        <div class="scan-list">
            {#each filtered as item (item.timestamp)}
                <div class="scan-item">
                    <div class="dot-wrap">
                        <span
                            class="status-dot"
                            style="background:{statusColor(
                                item.status,
                            )}; box-shadow:0 0 5px {statusColor(item.status)}"
                        ></span>
                    </div>
                    <div class="scan-info">
                        <span class="scan-url">{fmtUrl(item.url)}</span>
                        <span class="scan-meta">
                            {fmtDate(item.timestamp)}
                            {fmtTime(item.timestamp)}
                            {#if item.scanMs}
                                · {item.scanMs}ms{/if}
                            {#if item.riskScore !== undefined}
                                · Risk {item.riskScore}{/if}
                        </span>
                        {#if item.threatType}
                            <span class="threat-label">{item.threatType}</span>
                        {/if}
                    </div>
                    <span
                        class="scan-badge"
                        style="
            background:color-mix(in srgb, {statusColor(
                            item.status,
                        )} 10%, transparent);
            border:1px solid color-mix(in srgb, {statusColor(
                            item.status,
                        )} 30%, transparent);
            color:{statusColor(item.status)};
          ">{statusLabel(item.status)}</span
                    >
                </div>
            {/each}
        </div>
    {/if}
</div>

<style>
    .history-wrap {
        display: flex;
        flex-direction: column;
        gap: 10px;
    }

    .summary-row {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 7px;
    }
    .sum-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 8px 4px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 2px;
    }
    .sum-card.safe {
        border-color: rgba(16, 185, 129, 0.2);
        background: rgba(16, 185, 129, 0.04);
    }
    .sum-card.blocked {
        border-color: rgba(239, 68, 68, 0.2);
        background: rgba(239, 68, 68, 0.04);
    }
    .sum-num {
        font-size: 17px;
        font-weight: 700;
        font-family: var(--font-mono);
        color: var(--text-primary);
    }
    .sum-label {
        font-size: 8px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
    }
    .filters {
        display: flex;
        gap: 4px;
    }
    .filter-btn {
        padding: 3px 8px;
        border-radius: 100px;
        font-size: 9px;
        font-weight: 600;
        border: 1px solid var(--border);
        background: transparent;
        color: var(--text-muted);
        cursor: pointer;
        transition: all 0.15s;
        font-family: var(--font-main);
        letter-spacing: 0.03em;
    }
    .filter-btn:hover {
        border-color: var(--border-glow);
        color: var(--text-secondary);
    }
    .filter-btn.active {
        border-color: var(--accent);
        color: var(--accent);
        background: rgba(59, 130, 246, 0.08);
    }

    .actions {
        display: flex;
        gap: 4px;
    }
    .action-btn {
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 9px;
        font-weight: 600;
        border: 1px solid var(--border);
        background: transparent;
        color: var(--text-muted);
        cursor: pointer;
        transition: all 0.15s;
        font-family: var(--font-main);
    }
    .action-btn:hover {
        border-color: var(--border-glow);
        color: var(--text-secondary);
    }
    .action-btn.danger {
        border-color: var(--accent-red);
        color: var(--accent-red);
        background: rgba(239, 68, 68, 0.08);
    }

    .empty-state {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 8px;
        padding: 32px 0;
    }
    .empty-icon {
        font-size: 28px;
        opacity: 0.4;
    }
    .empty-txt {
        font-size: 11px;
        color: var(--text-muted);
        text-align: center;
        font-family: var(--font-mono);
    }

    .scan-list {
        display: flex;
        flex-direction: column;
        gap: 5px;
    }
    .scan-item {
        display: flex;
        align-items: center;
        gap: 9px;
        padding: 8px 11px;
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        transition: border-color 0.15s;
    }
    .scan-item:hover {
        border-color: var(--border-glow);
    }

    .dot-wrap {
        flex-shrink: 0;
    }
    .status-dot {
        display: block;
        width: 7px;
        height: 7px;
        border-radius: 50%;
    }

    .scan-info {
        flex: 1;
        min-width: 0;
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .scan-url {
        font-size: 10px;
        font-family: var(--font-mono);
        color: var(--text-secondary);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .scan-meta {
        font-size: 8.5px;
        color: var(--text-muted);
    }
    .threat-label {
        font-size: 8px;
        color: var(--accent-red);
        font-family: var(--font-mono);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .scan-badge {
        font-size: 8.5px;
        font-weight: 700;
        white-space: nowrap;
        padding: 2px 7px;
        border-radius: 100px;
        flex-shrink: 0;
        font-family: var(--font-mono);
        letter-spacing: 0.04em;
    }
</style>
