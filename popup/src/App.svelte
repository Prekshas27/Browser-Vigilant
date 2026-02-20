<script>
  import "./app.css";
  import { onMount } from "svelte";
  import Shield from "./components/Shield.svelte";
  import History from "./components/History.svelte";
  import ThreatMap from "./components/ThreatMap.svelte";
  import Settings from "./components/Settings.svelte";
  import Vault from "./components/Vault.svelte";
  import shieldLogo from "./assets/shield.png";

  let activeTab = "shield";
  let isLightMode = false;

  // State loaded from background.js via chrome.runtime.sendMessage
  let tabState = null;
  let settings = null;
  let stats = null;
  let history = [];
  let chain = [];
  let chainTampered = false;
  let merkleRoot = null;
  let localVault = [];
  let syncMeta = null;
  let loading = true;
  let currentTabId = null;
  let currentTabUrl = ""; // passed to Shield for instant auto-scan

  const tabs = [
    { id: "shield", label: "Shield" },
    { id: "history", label: "History" },
    { id: "ledger", label: "Ledger" },
    { id: "vault", label: "Vault" },
    { id: "settings", label: "Settings" },
  ];

  onMount(async () => {
    // Check localStorage for preferred theme
    if (localStorage.getItem("theme") === "light") {
      isLightMode = true;
      document.documentElement.classList.add("light-theme");
    }

    if (typeof chrome === "undefined" || !chrome?.runtime?.sendMessage) {
      loading = false;
      return;
    }
    try {
      const [tab] = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });
      currentTabId = tab?.id ?? null;
      currentTabUrl = tab?.url ?? "";

      const res = await chrome.runtime.sendMessage({
        type: "GET_STATE",
        tabId: currentTabId,
      });

      tabState = res.tabState ?? null;
      settings = res.settings ?? null;
      stats = res.stats ?? null;
      history = res.history ?? [];
      chain = res.chain ?? [];
      chainTampered = res.chainTampered ?? false;
      merkleRoot = res.merkleRoot ?? null;
      localVault = res.localVault ?? [];
      syncMeta = res.syncMeta ?? null;

      // If tabState is null but URL is a real web page, retry once after a
      // short delay — content.js may still be running its scan
      const isScannableUrl =
        currentTabUrl.startsWith("http://") ||
        currentTabUrl.startsWith("https://");
      if (!tabState && isScannableUrl) {
        await new Promise((r) => setTimeout(r, 1500));
        const res2 = await chrome.runtime.sendMessage({
          type: "GET_STATE",
          tabId: currentTabId,
        });
        if (res2.tabState) tabState = res2.tabState;
        // Refresh stats too
        if (res2.stats) stats = res2.stats;
      }
    } catch (e) {
      console.warn("[BV Popup] Could not load state:", e);
    } finally {
      loading = false;
    }
  });

  // When settings change inside Settings.svelte, persist and refresh
  async function onSettingsChange(newSettings) {
    settings = newSettings;
    if (typeof chrome !== "undefined" && chrome?.runtime?.sendMessage) {
      await chrome.runtime.sendMessage({
        type: "SAVE_SETTINGS",
        settings: newSettings,
      });
    }
  }

  async function onClearHistory() {
    if (typeof chrome !== "undefined" && chrome?.runtime?.sendMessage) {
      await chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" });
      history = [];
    }
  }

  async function handleRemoveFlag(domain_hash) {
    if (typeof chrome !== "undefined" && chrome?.runtime?.sendMessage) {
      await chrome.runtime.sendMessage({ type: "REMOVE_FLAG", domain_hash });
      localVault = localVault.filter((t) => t.domain_hash !== domain_hash);
    }
  }

  function toggleTheme() {
    isLightMode = !isLightMode;
    if (isLightMode) {
      document.documentElement.classList.add("light-theme");
      localStorage.setItem("theme", "light");
    } else {
      document.documentElement.classList.remove("light-theme");
      localStorage.setItem("theme", "dark");
    }
  }

  $: threatBlocks = chain.filter((b) => b.type === "THREAT_BLOCKED").length;
</script>

<div class="popup-root">
  <!-- Header -->
  <header class="header">
    <div class="logo">
      <img
        src={shieldLogo}
        class="logo-shield {settings?.protection === false
          ? 'paused-logo'
          : ''}"
        alt="Browser Vigilant Logo"
        width="28"
        height="28"
      />
      <div class="logo-text">
        <span class="logo-name">Browser Vigilant</span>
        <span
          class="logo-status {settings?.protection === false
            ? 'paused'
            : 'active'}"
        >
          {settings?.protection === false ? "Paused" : "Active"}
        </span>
      </div>
    </div>

    <div class="header-actions">
      <button
        class="icon-btn"
        on:click={() =>
          (activeTab = activeTab === "settings" ? "shield" : "settings")}
        aria-label="Settings"
      >
        <svg
          width="18"
          height="18"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
          ><circle cx="12" cy="12" r="3"></circle><path
            d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"
          ></path></svg
        >
      </button>
    </div>
  </header>

  <!-- Tab bar -->
  <nav class="tabs">
    {#each tabs as tab}
      <button
        class="tab-btn {activeTab === tab.id ? 'active' : ''}"
        on:click={() => (activeTab = tab.id)}
        id="tab-{tab.id}"
      >
        <span>{tab.label}</span>
      </button>
    {/each}
  </nav>

  <!-- Content -->
  <main class="content">
    {#if loading}
      <div class="loader-wrap">
        <div class="loader-ring"></div>
        <p class="loader-txt">Loading engine state…</p>
      </div>
    {:else if activeTab === "shield"}
      <Shield {tabState} {stats} {settings} tabUrl={currentTabUrl} />
    {:else if activeTab === "history"}
      <div class="tab-page">
        <History {history} onClear={onClearHistory} />
      </div>
    {:else if activeTab === "ledger"}
      <div class="tab-page">
        <ThreatMap {chain} {chainTampered} />
      </div>
    {:else if activeTab === "vault"}
      <div class="tab-page">
        <Vault
          {localVault}
          {syncMeta}
          {merkleRoot}
          onRemoveFlag={handleRemoveFlag}
        />
      </div>
    {:else if activeTab === "settings"}
      <div class="tab-page">
        <Settings {settings} onChange={onSettingsChange} />
      </div>
    {/if}
  </main>
</div>

<style>
  .popup-root {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 540px;
    max-height: 600px;
    background: var(--bg-primary);
    overflow: hidden;
  }

  /* Header */
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 24px 24px 20px;
    background: transparent;
    flex-shrink: 0;
    z-index: 10;
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .logo-shield {
    flex-shrink: 0;
    transition: all 0.2s;
  }
  .paused-logo {
    filter: grayscale(1) opacity(0.5);
  }
  .logo-text {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .logo-name {
    font-size: 16px;
    font-weight: 800;
    color: var(--text-primary);
    letter-spacing: -0.02em;
    line-height: 1.1;
  }
  .logo-status {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.05em;
    line-height: 1;
  }
  .logo-status.active {
    color: #34d399;
  }
  .logo-status.paused {
    color: var(--text-muted);
  }
  .header-actions {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .icon-btn {
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: color 0.2s;
  }
  .icon-btn:hover {
    color: var(--text-primary);
  }

  /* Tabs */
  .tabs {
    display: flex;
    background: transparent;
    padding: 0 24px;
    gap: 8px;
    margin-bottom: 20px;
  }
  .tab-btn {
    flex: 1;
    background: var(--bg-secondary);
    border: 1px solid transparent;
    border-radius: 100px;
    color: var(--text-secondary);
    font-size: 13px;
    font-weight: 700;
    padding: 10px 0;
    cursor: pointer;
    font-family: var(--font-main);
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .tab-btn:hover {
    color: var(--text-primary);
    background: rgba(0, 0, 0, 0.04);
  }
  .tab-btn.active {
    background: var(--bg-card);
    flex-shrink: 0;
  }
  .tab-btn {
    flex: 1;
    background: var(--bg-secondary);
    border: 1px solid transparent;
    border-radius: 100px;
    color: var(--text-secondary);
    font-size: 13px;
    font-weight: 700;
    padding: 10px 0;
    cursor: pointer;
    font-family: var(--font-main);
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .tab-btn:hover {
    color: var(--text-primary);
    background: rgba(0, 0, 0, 0.04);
  }
  .tab-btn.active {
    background: var(--bg-card);
    border-color: transparent;
    color: var(--text-primary);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.06);
  }

  /* Content */
  .content {
    flex: 1;
    overflow-y: auto;
    padding: 0;
    background: var(--bg-primary);
  }
  .tab-page {
    padding: 4px 20px 24px;
  }

  /* Loader */
  .loader-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 14px;
  }
  .loader-ring {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    border: 2px solid transparent;
    border-top-color: var(--accent);
    border-right-color: var(--accent);
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .loader-txt {
    font-size: 11px;
    color: var(--text-muted);
    font-family: var(--font-mono);
  }

  /* Footer */
  .footer {
    padding: 6px 14px;
    border-top: 1px solid var(--border);
    background: var(--bg-secondary);
    flex-shrink: 0;
  }
  .footer-txt {
    font-size: 8px;
    color: var(--text-muted);
    font-family: var(--font-mono);
    letter-spacing: 0.04em;
    display: block;
    text-align: center;
  }
</style>
