<script>
    export let localVault = [];
    export let syncMeta = null;
    export let merkleRoot = null;
    export let onRemoveFlag = () => {};

    $: localBlocked = localVault.length;
    $: pendingFlags = localVault.filter((t) => t.status === "pending").length;
    $: verifiedThreats = localVault.filter(
        (t) => t.status === "verified",
    ).length;
    $: manualFlags = localVault.filter((t) => t.source === "manual");

    // Cloud Stats
    $: communityCount = syncMeta?.cloud_hash_count || 0;
    $: lastSync = syncMeta?.last_sync_time
        ? new Date(syncMeta.last_sync_time).toLocaleString()
        : "Never";
    $: lastDelta = syncMeta?.last_sync_delta || 0;
</script>

<div class="vault-view">
    <div class="stats-section">
        <h3>Local Stats</h3>
        <div class="grid">
            <div class="card">
                <span class="num">{localBlocked}</span>
                <span class="label">Locally Blocked</span>
            </div>
            <div class="card">
                <span class="num">{pendingFlags}</span>
                <span class="label">Pending Flags</span>
            </div>
            <div class="card">
                <span class="num">{verifiedThreats}</span>
                <span class="label">Verified Threats</span>
            </div>
        </div>
    </div>

    <div class="stats-section">
        <h3>Cloud Stats</h3>
        <div class="grid">
            <div class="card bg-accent">
                <span class="num">{communityCount}</span>
                <span class="label">Community Threats</span>
            </div>
            <div class="card">
                <span class="num">+{lastDelta}</span>
                <span class="label">New Hashes</span>
            </div>
            <div class="card flex2">
                <span class="numtext">{lastSync}</span>
                <span class="label">Last Sync</span>
            </div>
        </div>
    </div>

    <div class="stats-section">
        <h3>Data Integrity</h3>
        <div class="card full-width">
            <span class="hash-text" title={merkleRoot}
                >{merkleRoot
                    ? merkleRoot.slice(0, 32) + "..."
                    : "Unknown"}</span
            >
            <span class="label">Vault Integrity Hash (Root)</span>
        </div>
    </div>

    <div class="flags-section">
        <h3>Manual Flags ({manualFlags.length})</h3>
        {#if manualFlags.length === 0}
            <p class="empty-txt">No manual flags yet.</p>
        {:else}
            <div class="list">
                {#each manualFlags as flag}
                    <div class="flag-item">
                        <div class="f-info">
                            <span class="f-hash" title={flag.domain_hash}
                                >{flag.domain_hash.slice(0, 16)}...</span
                            >
                            <span class="f-status badge-{flag.status}"
                                >{flag.status}</span
                            >
                            <span class="f-trust" title="Trust Score"
                                >★ {flag.trust_score || 0}</span
                            >
                        </div>
                        <button
                            class="f-rem"
                            on:click={() => onRemoveFlag(flag.domain_hash)}
                            >Remove</button
                        >
                    </div>
                {/each}
            </div>
        {/if}
    </div>
</div>

<style>
    .vault-view {
        display: flex;
        flex-direction: column;
        gap: 20px;
    }
    h3 {
        font-size: 14px;
        color: var(--text-primary);
        margin-bottom: 12px;
    }
    .grid {
        display: flex;
        gap: 12px;
    }
    .card {
        flex: 1;
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        text-align: center;
    }
    .card.bg-accent {
        background: rgba(59, 130, 246, 0.1);
        border-color: rgba(59, 130, 246, 0.2);
    }
    .card.flex2 {
        flex: 2;
    }
    .card.full-width {
        width: 100%;
        padding: 16px;
    }
    .hash-text {
        font-family: var(--font-mono);
        font-size: 11px;
        color: var(--text-secondary);
        word-break: break-all;
    }
    .num {
        font-size: 20px;
        font-weight: 800;
        color: var(--text-primary);
    }
    .numtext {
        font-size: 13px;
        font-weight: 600;
        color: var(--text-primary);
    }
    .label {
        font-size: 10px;
        color: var(--text-muted);
        margin-top: 4px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .list {
        display: flex;
        flex-direction: column;
        gap: 8px;
    }
    .flag-item {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 10px 12px;
    }
    .f-info {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .f-hash {
        font-family: var(--font-mono);
        font-size: 12px;
        color: var(--text-secondary);
    }
    .f-status {
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        padding: 2px 6px;
        border-radius: 4px;
        background: var(--bg-secondary);
    }
    .f-trust {
        font-size: 10px;
        font-weight: 700;
        color: #f59e0b;
        background: rgba(245, 158, 11, 0.1);
        padding: 2px 6px;
        border-radius: 4px;
    }
    .f-status.badge-pending {
        color: #f59e0b;
        background: rgba(245, 158, 11, 0.1);
    }
    .f-status.badge-verified {
        color: #ef4444;
        background: rgba(239, 68, 68, 0.1);
    }
    .f-status.badge-rejected {
        color: #10b981;
        background: rgba(16, 185, 129, 0.1);
    }
    .f-rem {
        background: transparent;
        border: 1px solid var(--border);
        color: #ef4444;
        border-radius: 6px;
        padding: 4px 8px;
        font-size: 11px;
        cursor: pointer;
        transition: all 0.2s;
    }
    .f-rem:hover {
        background: rgba(239, 68, 68, 0.1);
        border-color: #ef4444;
    }
    .empty-txt {
        font-size: 13px;
        color: var(--text-muted);
    }
</style>
