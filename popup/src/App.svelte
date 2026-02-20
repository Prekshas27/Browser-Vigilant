<script>
  import "./app.css";
  import { onMount } from "svelte";
  import Shield from "./components/Shield.svelte";
  import History from "./components/History.svelte";
  import ThreatMap from "./components/ThreatMap.svelte";
  import Settings from "./components/Settings.svelte";

  let activeTab = "shield";
  let isLightMode = false;

  // State loaded from background.js via chrome.runtime.sendMessage
  let tabState = null;
  let settings = null;
  let stats = null;
  let history = [];
  let chain = [];
  let chainTampered = false;
  let loading = true;
  let currentTabId = null;
  let currentTabUrl = ""; // passed to Shield for instant auto-scan

  const tabs = [
    { id: "shield", label: "Shield" },
    { id: "history", label: "History" },
    { id: "ledger", label: "Ledger" },
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
      <div class="logo-icon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
          <path
            d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"
            fill="url(#sg)"
            stroke="rgba(99,179,237,0.4)"
            stroke-width="0.5"
          />
          <path
            d="M9.5 12.5l2 2 4-4"
            stroke="#f0f4ff"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
          <defs>
            <linearGradient
              id="sg"
              x1="3"
              y1="2"
              x2="21"
              y2="23"
              gradientUnits="userSpaceOnUse"
            >
              <stop stop-color="#3b82f6" />
              <stop offset="1" stop-color="#1d4ed8" />
            </linearGradient>
          </defs>
        </svg>
      </div>
      <div class="logo-text">
        <span class="logo-name">Browser Vigilant</span>
        <span class="logo-sub">v2.0 · AI+Blockchain Engine</span>
      </div>
    </div>

    <div class="header-actions">
      <button
        class="theme-toggle"
        on:click={toggleTheme}
        aria-label="Toggle Theme"
        title={isLightMode ? "Switch to Dark Mode" : "Switch to Light Mode"}
      >
        {isLightMode ? "🌙" : "☀️"}
      </button>

      <div
        class="status-badge {settings?.protection === false
          ? 'paused'
          : 'active'}"
      >
        <span class="status-dot"></span>
        {settings?.protection === false ? "Paused" : "Active"}
      </div>
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
      <Shield {tabState} {stats} tabUrl={currentTabUrl} />
    {:else if activeTab === "history"}
      <History {history} onClear={onClearHistory} />
    {:else if activeTab === "ledger"}
      <ThreatMap {chain} {chainTampered} />
    {:else if activeTab === "settings"}
      <Settings {settings} onChange={onSettingsChange} />
    {/if}
  </main>

  <!-- Footer -->
  <footer class="footer">
    <span class="footer-txt"
      >100% On-Device · Zero Data Leaks · Rust WASM · SHA-256 Ledger</span
    >
  </footer>
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
    padding: 12px 14px 10px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
    flex-shrink: 0;
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 9px;
  }
  .logo-icon {
    width: 34px;
    height: 34px;
    background: linear-gradient(
      135deg,
      rgba(59, 130, 246, 0.18),
      rgba(29, 78, 216, 0.08)
    );
    border: 1px solid rgba(59, 130, 246, 0.28);
    border-radius: 9px;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 0 10px rgba(59, 130, 246, 0.12);
  }
  .logo-text {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .logo-name {
    font-size: 12px;
    font-weight: 700;
    color: var(--text-primary);
    letter-spacing: 0.02em;
  }
  .logo-sub {
    font-size: 8px;
    color: var(--text-muted);
    font-family: var(--font-mono);
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .theme-toggle {
    background: transparent;
    border: none;
    cursor: pointer;
    font-size: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 6px;
    border-radius: 8px;
    transition: background 0.2s;
  }
  .theme-toggle:hover {
    background: var(--bg-card-hover);
  }

  .status-badge {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 4px 10px;
    border-radius: 100px;
  }
  .status-badge.active {
    border: 1px solid var(--accent-green);
    color: var(--accent-green);
    background: rgba(16, 185, 129, 0.08);
  }
  .status-badge.paused {
    border: 1px solid var(--text-muted);
    color: var(--text-muted);
    background: rgba(255, 255, 255, 0.04);
  }
  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
  }
  .status-badge.active .status-dot {
    background: var(--accent-green);
  }
  .status-badge.paused .status-dot {
    background: var(--text-muted);
  }

  /* Tabs */
  .tabs {
    display: flex;
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
    padding: 0 6px;
    flex-shrink: 0;
  }
  .tab-btn {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 4px;
    padding: 8px 2px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    font-family: var(--font-main);
    font-size: 10px;
    font-weight: 500;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    position: relative;
    bottom: -1px;
    transition: all 0.18s ease;
    letter-spacing: 0.02em;
  }
  .tab-btn:hover {
    color: var(--text-secondary);
  }
  .tab-btn.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }
  .tab-icon {
    font-size: 13px;
  }

  /* Content */
  .content {
    flex: 1;
    overflow-y: auto;
    padding: 14px;
    background: var(--bg-primary);
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
