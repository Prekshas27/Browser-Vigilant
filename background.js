/**
 * background.js — Browser Vigilant Service Worker
 *
 * Responsibilities:
 *  1. Receive SCAN_RESULT messages from content.js
 *  2. Build and maintain a real SHA-256 blockchain threat ledger
 *  3. Persist scan history to chrome.storage.local
 *  4. Intercept file downloads and score them
 *  5. Manage extension badge (green ✓ / red ✗)
 *  6. Respond to GET_STATE queries from the popup
 *  7. Emit THREAT_NOTIFICATION for dangerous downloads
 */

// ── Storage keys ─────────────────────────────────────────────────────────────
const KEYS = {
    HISTORY: "bv_scan_history",
    VAULT: "bv_threat_vault",   // Merkle Threat Vault (replaces chain key)
    STATS: "bv_stats",
    SETTINGS: "bv_settings",
    TAB_STATE: "bv_tab_state",
};
// Legacy alias so old chain reads still work during migration
const CHAIN_LEGACY_KEY = "bv_threat_chain";

const MAX_HISTORY = 100;
const API_BASE = "http://localhost:3000/api/vault";  // Kept as http to match CSP, can be changed to https if needed

const DEFAULT_SETTINGS = {
    protection: true,
    autoBlock: true,
    blockThreshold: 0.50,   // ML probability threshold
    upiDetection: true,
    downloadScanner: true,
    domAnalysis: true,
    notifications: true,
    strictMode: false,
};


// ── Merkle Threat Vault — in-memory hash cache ────────────────────────────────
// SHA-256(hostname) of every confirmed-blocked domain.
// O(1) lookup. Rebuilt from vault on startup. Never stores raw URLs.
let blockedDomainHashes = new Set();
let merkleRoot = null; // current Merkle root hash — proves vault integrity

/**
 * Merkle root = SHA-256 of all leaf hashes sorted and concatenated.
 * Matches standard Merkle tree root for a sorted list.
 * O(n) to compute.  Verified on reload to detect tampering.
 */
async function computeMerkleRoot(hashes) {
    if (!hashes || hashes.length === 0) return "0".repeat(64);
    const sorted = [...hashes].sort();
    const combined = sorted.join("");
    return sha256(combined);
}

async function rebuildVaultCache() {
    const data = await chrome.storage.local.get(KEYS.VAULT);
    const vault = data[KEYS.VAULT] || { blocks: [], merkleRoot: "0".repeat(64) };
    blockedDomainHashes.clear();
    const allHashes = [];
    for (const block of vault.blocks) {
        if (block.domainHash) {
            blockedDomainHashes.add(block.domainHash);
            allHashes.push(block.domainHash);
        }
    }
    // Verify Merkle root integrity
    const computed = await computeMerkleRoot(allHashes);
    if (vault.blocks.length > 0 && computed !== vault.merkleRoot) {
        console.warn("[BV] Threat Vault Merkle root mismatch — vault may be tampered!");
        await chrome.storage.local.set({ bv_vault_tampered: true });
    } else {
        await chrome.storage.local.set({ bv_vault_tampered: false });
    }
    merkleRoot = computed;
    console.log(`[BV] Threat Vault loaded: ${blockedDomainHashes.size} blocked domains (Merkle root: ${computed.slice(0, 16)}...)`);
}

async function getVault() {
    const data = await chrome.storage.local.get(KEYS.VAULT);
    return data[KEYS.VAULT] || { blocks: [], merkleRoot: "0".repeat(64) };
}

async function checkVaultTamper() {
    const data = await chrome.storage.local.get("bv_vault_tampered");
    if (data.bv_vault_tampered) {
        console.warn("[BV] Previous vault tamper detected. Rebuilding cache but not trusting Merkle root.");
    }
}

// ── Init ──────────────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async () => {
    const existing = await chrome.storage.local.get(KEYS.VAULT);
    if (!existing[KEYS.VAULT]) {
        const genesis = await buildGenesisBlock();
        await chrome.storage.local.set({
            [KEYS.VAULT]: { blocks: [genesis], merkleRoot: genesis.hash },
            [KEYS.HISTORY]: [],
            [KEYS.STATS]: { totalScanned: 0, totalBlocked: 0, threatsToday: 0, lastReset: todayDateStr() },
            [KEYS.TAB_STATE]: {},
        });
    }
    await ensureSettingsDefaults();
    await rebuildVaultCache();
    console.log("[BV] Browser Vigilant v2.0 installed.");
    await syncThreatVault(); // Phase 5 community sync
});

chrome.runtime.onStartup.addListener(async () => {
    console.log("[BV] Startup – checking state...");
    await resetDailyStatsIfNeeded();
    await rebuildVaultCache();   // rebuilds in-memory Set + verifies Merkle root
    await ensureSettingsDefaults();
    await checkVaultTamper();
    await syncThreatVault(); // Phase 5 community sync
});

// ── SHA-256 via Web Crypto (available in service workers) ─────────────────────
async function sha256(data) {
    const encoded = new TextEncoder().encode(data);
    const buf = await crypto.subtle.digest("SHA-256", encoded);
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, "0")).join("");
}

// ── Blockchain ────────────────────────────────────────────────────────────────
async function buildGenesisBlock() {
    const block = {
        index: 0,
        timestamp: new Date().toISOString(),
        type: "GENESIS",
        url: null,
        threatType: null,
        signals: [],
        riskScore: null,
        mlProb: null,
        hScore: null,
        domScore: null,
        prevHash: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: 0,
    };
    block.hash = await hashBlock(block);
    return block;
}

async function hashBlock(block) {
    const data = `${block.index}${block.timestamp}${block.url}${JSON.stringify(block.signals)}${block.prevHash}${block.nonce}`;
    return sha256(data);
}

async function appendChainBlock(threatData) {
    const vault = await getVault();
    const prev = vault.blocks[vault.blocks.length - 1];

    // Compute domain hash for Merkle Threat Vault (SHA-256 of hostname only)
    // Raw URL is NOT stored in the domain hash — only hostname, one-way hash
    const domain = (() => {
        try { return new URL(threatData.url).hostname.toLowerCase(); }
        catch { return threatData.url; }
    })();
    const domainHash = await sha256(domain);

    const block = {
        index: prev.index + 1,
        timestamp: new Date().toISOString(),
        type: "THREAT_BLOCKED",
        // Privacy: store only truncated URL (no path/query) + domain hash
        urlSummary: (() => { try { return new URL(threatData.url).hostname; } catch { return "unknown"; } })(),
        domainHash,             // SHA-256(hostname) — irreversible, no PII
        threatType: threatData.threatType,
        signals: threatData.signals,
        riskScore: threatData.riskScore,
        mlProb: threatData.mlProb ?? null,
        hScore: threatData.hScore ?? null,
        domScore: threatData.domScore ?? null,
        layer: threatData.layer ?? "heuristic", // which layer caught it
        prevHash: prev.hash,
        nonce: crypto.getRandomValues(new Uint32Array(1))[0],
    };
    block.hash = await hashBlock(block);
    vault.blocks.push(block);

    // Update Merkle root
    const allHashes = vault.blocks.filter(b => b.domainHash).map(b => b.domainHash);
    vault.merkleRoot = await computeMerkleRoot(allHashes);

    await chrome.storage.local.set({ [KEYS.VAULT]: vault });

    // Update in-memory cache immediately — O(1) future lookups
    blockedDomainHashes.add(domainHash);
    merkleRoot = vault.merkleRoot;

    // Phase 5: Submit zero-day threat to Community Vault in background
    submitThreatToVault(domainHash, block.dangerScore || 0.95);

    return block;
}

// ── Decentralized Community Threat Vault ──────────────────────────────────────
async function submitThreatToVault(hash, confidence = 1.0) {
    try {
        await fetch(`${API_BASE}/submit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash, source: 'extension-ml', confidence })
        });
        console.log(`[BV Vault] Submitted threat hash to community vault: ${hash.slice(0, 8)}...`);
    } catch {
        // Soft fail if server is unreachable
    }
}

async function syncThreatVault() {
    try {
        const { bv_last_sync } = await chrome.storage.local.get("bv_last_sync");
        const since = bv_last_sync || 0;

        const res = await fetch(`${API_BASE}/sync?since=${since}&clientId=extension`);
        if (!res.ok) return;

        const data = await res.json();
        if (data && data.hashes && data.hashes.length > 0) {
            // Add all inbound community hashes to local memory cache instantly
            data.hashes.forEach(h => blockedDomainHashes.add(h));
            await chrome.storage.local.set({ "bv_last_sync": Date.now() });
            console.log(`[BV Vault] Synced ${data.hashes.length} new community threats.`);
        }
    } catch {
        // Soft fail if server unreachable
    }
}

// ── Settings ──────────────────────────────────────────────────────────────────
async function ensureSettingsDefaults() {
    const { [KEYS.SETTINGS]: stored } = await chrome.storage.sync.get(KEYS.SETTINGS);
    const merged = { ...DEFAULT_SETTINGS, ...(stored || {}) };
    await chrome.storage.sync.set({ [KEYS.SETTINGS]: merged });
    return merged;
}

async function getSettings() {
    const { [KEYS.SETTINGS]: s } = await chrome.storage.sync.get(KEYS.SETTINGS);
    return s || DEFAULT_SETTINGS;
}

// ── History storage ───────────────────────────────────────────────────────────
async function recordScan(entry) {
    const { [KEYS.HISTORY]: history } = await chrome.storage.local.get(KEYS.HISTORY);
    const log = history || [];
    log.unshift({ ...entry, timestamp: new Date().toISOString() });
    if (log.length > MAX_HISTORY) log.length = MAX_HISTORY;
    await chrome.storage.local.set({ [KEYS.HISTORY]: log });
}

async function updateStats(blocked) {
    const { [KEYS.STATS]: stats } = await chrome.storage.local.get(KEYS.STATS);
    const s = stats || { totalScanned: 0, totalBlocked: 0, threatsToday: 0, lastReset: todayDateStr() };
    if (s.lastReset !== todayDateStr()) {
        s.threatsToday = 0;
        s.lastReset = todayDateStr();
    }
    s.totalScanned += 1;
    if (blocked) { s.totalBlocked += 1; s.threatsToday += 1; }
    await chrome.storage.local.set({ [KEYS.STATS]: s });
    return s;
}

async function resetDailyStatsIfNeeded() {
    const { [KEYS.STATS]: stats } = await chrome.storage.local.get(KEYS.STATS);
    if (stats && stats.lastReset !== todayDateStr()) {
        await chrome.storage.local.set({
            [KEYS.STATS]: { ...stats, threatsToday: 0, lastReset: todayDateStr() }
        });
    }
}

// ── Tab state ─────────────────────────────────────────────────────────────────
async function setTabState(tabId, state) {
    const { [KEYS.TAB_STATE]: ts } = await chrome.storage.local.get(KEYS.TAB_STATE);
    const tabState = ts || {};
    tabState[tabId] = state;
    await chrome.storage.local.set({ [KEYS.TAB_STATE]: tabState });
}

async function getTabState(tabId) {
    const { [KEYS.TAB_STATE]: ts } = await chrome.storage.local.get(KEYS.TAB_STATE);
    return (ts || {})[tabId] || null;
}

// ── Badge helpers ─────────────────────────────────────────────────────────────
function setBadge(tabId, status, count) {
    if (status === "threat") {
        chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId });
        chrome.action.setBadgeText({ text: "✕", tabId });
    } else if (status === "warning") {
        chrome.action.setBadgeBackgroundColor({ color: "#f59e0b", tabId });
        chrome.action.setBadgeText({ text: "!", tabId });
    } else if (status === "safe") {
        chrome.action.setBadgeBackgroundColor({ color: "#10b981", tabId });
        chrome.action.setBadgeText({ text: "✓", tabId });
    } else {
        chrome.action.setBadgeText({ text: "", tabId });
    }
}

// ── Message handler ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender).then(sendResponse).catch(e => {
        console.error("[BV] Message error:", e);
        sendResponse({ error: e.message });
    });
    return true; // keep channel open for async
});

async function handleMessage(message, sender) {
    const { type } = message;

    if (type === "SCAN_RESULT") {
        const { result, tabId } = message;
        const settings = await getSettings();
        if (!settings.protection) return { ack: true };

        // Persist tab state
        await setTabState(tabId || sender.tab?.id, result);

        // Record in history
        await recordScan({
            url: result.url,
            status: result.verdict,
            scanMs: result.scanMs,
            riskScore: result.riskScore,
            mlProb: result.mlProb,
            hScore: result.hScore,
            domScore: result.domScore,
            signals: result.signals,
            threatType: result.threatType,
        });

        // Update stats
        const stats = await updateStats(result.verdict === "threat");

        // Badge
        const tid = tabId || sender.tab?.id;
        if (tid) setBadge(tid, result.verdict, stats.threatsToday);

        // Blockchain ledger for confirmed threats
        if (result.verdict === "threat") {
            await appendChainBlock({
                url: result.url,
                threatType: result.threatType,
                signals: result.signals,
                riskScore: result.riskScore,
                mlProb: result.mlProb,
                hScore: result.hScore,
                domScore: result.domScore,
            });

            // Notification
            if (settings.notifications) {
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icons/icon48.png",
                    title: "🛡 Browser Vigilant — Threat Blocked",
                    message: `${result.threatType} detected on ${truncateUrl(result.url, 50)}`,
                    priority: 2,
                });
            }
        }

        return { ack: true, stats };
    }

    if (type === "GET_STATE") {
        const { tabId } = message;
        const [tabState, settings, stats, history, vault, tampered] = await Promise.all([
            getTabState(tabId),
            getSettings(),
            chrome.storage.local.get(KEYS.STATS).then(r => r[KEYS.STATS] || { totalScanned: 0, totalBlocked: 0, threatsToday: 0 }),
            chrome.storage.local.get(KEYS.HISTORY).then(r => r[KEYS.HISTORY] || []),
            getVault(),
            chrome.storage.local.get("bv_vault_tampered").then(r => r.bv_vault_tampered || false),
        ]);
        return {
            tabState, settings, stats, history,
            chain: vault.blocks,            // popup still uses 'chain' key for compatibility
            chainTampered: tampered,
            merkleRoot: vault.merkleRoot,
            vaultSize: blockedDomainHashes.size,
        };
    }

    // ── SCAN_URL: popup scanner delegates heuristics to background ────────────
    // This removes the duplicated quickScan() from Shield.svelte.
    if (type === "SCAN_URL") {
        const result = prenavScan(message.url || "");
        // Also check vault for instant match
        try {
            const domain = new URL(message.url).hostname.toLowerCase();
            const dHash = await sha256(domain);
            if (blockedDomainHashes.has(dHash)) {
                return {
                    verdict: "threat",
                    riskScore: 100,
                    signals: ["Previously confirmed threat (Threat Vault match)"],
                    threatType: "Threat Vault: Confirmed Blocked Domain",
                    source: "vault",
                };
            }
        } catch { /* ignore parse errors */ }
        return result;
    }

    if (type === "SAVE_SETTINGS") {
        const merged = { ...DEFAULT_SETTINGS, ...message.settings };
        await chrome.storage.sync.set({ [KEYS.SETTINGS]: merged });
        return { ack: true };
    }

    if (type === "CLEAR_HISTORY") {
        await chrome.storage.local.set({ [KEYS.HISTORY]: [] });
        return { ack: true };
    }

    if (type === "DOWNLOAD_THREAT") {
        const { filename, url, riskScore } = message;
        const settings = await getSettings();
        if (!settings.downloadScanner) return { block: false };

        const shouldBlock = riskScore >= 0.6;
        if (shouldBlock) {
            await recordScan({
                url, status: "threat", scanMs: 0,
                riskScore: Math.round(riskScore * 100),
                signals: [`Malicious file: ${filename}`],
                threatType: "MALWARE_DOWNLOAD",
            });
            await updateStats(true);
            await appendChainBlock({
                url, threatType: "MALWARE_DOWNLOAD",
                signals: [`${filename}`],
                riskScore: Math.round(riskScore * 100),
            });
            if (settings.notifications) {
                chrome.notifications.create({
                    type: "basic", iconUrl: "icons/icon48.png",
                    title: "⚠ Download Blocked — Malicious File",
                    message: `${filename} was blocked (risk: ${Math.round(riskScore * 100)}%)`,
                    priority: 2,
                });
            }
        }
        return { block: shouldBlock };
    }

    return { error: "Unknown message type" };
}

// ── Download interception ─────────────────────────────────────────────────────
const DANGEROUS_EXTENSIONS = new Set([
    "exe", "scr", "bat", "cmd", "ps1", "vbs", "wsf", "hta", "jar", "msi", "msp",
    "reg", "dll", "pif", "com", "cpl", "inf", "apk", "ipa", "dmg",
]);

const DOUBLE_EXT_PATTERN = /\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|mp4|zip)\.(exe|js|php|bat|ps1|vbs|cmd|scr|dll)$/i;

function filenameEntropy(name) {
    if (!name) return 0;
    const freq = {};
    for (const c of name) freq[c] = (freq[c] || 0) + 1;
    const n = name.length;
    return -Object.values(freq).reduce((s, f) => s + (f / n) * Math.log2(f / n), 0);
}

function scoreFilename(filename, referrerUrl) {
    const low = filename.toLowerCase();
    const ext = low.split(".").pop();
    let score = 0;
    if (DANGEROUS_EXTENSIONS.has(ext)) score += 0.6;
    if (DOUBLE_EXT_PATTERN.test(low)) score += 0.4;
    const entropy = filenameEntropy(filename);
    if (entropy > 4.5) score += 0.2;
    // Brand + executable pattern
    const BRANDS = ["google", "microsoft", "adobe", "apple", "amazon", "paypal", "netflix", "chrome", "windows", "office"];
    if (BRANDS.some(b => low.includes(b)) && DANGEROUS_EXTENSIONS.has(ext)) score += 0.3;
    // Misleading extension in name
    if (/\.(pdf|jpg|png|docx?)\.(exe|bat|scr|vbs)/i.test(low)) score += 0.5;
    return Math.min(score, 1.0);
}

chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
    const filename = downloadItem.filename;
    const url = downloadItem.url;
    const score = scoreFilename(filename, url);

    if (score >= 0.6) {
        // Pause the download immediately
        chrome.downloads.pause(downloadItem.id);
        chrome.runtime.sendMessage({
            type: "DOWNLOAD_THREAT",
            filename, url, riskScore: score,
        }).then(res => {
            if (res?.block) {
                chrome.downloads.cancel(downloadItem.id);
            } else {
                chrome.downloads.resume(downloadItem.id);
            }
        }).catch(() => {
            // If popup not open, still block high-risk
            if (score >= 0.8) chrome.downloads.cancel(downloadItem.id);
            else chrome.downloads.resume(downloadItem.id);
        });
    }
    suggest({ filename });
    return true;
});

// ── Tab cleanup ───────────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener(async (tabId) => {
    const { [KEYS.TAB_STATE]: ts } = await chrome.storage.local.get(KEYS.TAB_STATE);
    if (ts && ts[tabId]) {
        delete ts[tabId];
        await chrome.storage.local.set({ [KEYS.TAB_STATE]: ts });
    }
});

// ── Utilities ─────────────────────────────────────────────────────────────────
function todayDateStr() {
    return new Date().toISOString().slice(0, 10);
}

function truncateUrl(url, max) {
    return url.length > max ? url.slice(0, max - 3) + "..." : url;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRE-NAVIGATION SCANNER
// Fires BEFORE the page loads using webNavigation.onBeforeNavigate.
// Runs a fast heuristic scan (< 2ms) on the URL.
// → WARNING  : shows OS notification immediately
// → THREAT   : redirects to block.html before page loads
// ═══════════════════════════════════════════════════════════════════════════════

const PRENAV_BRANDS = ["google", "facebook", "amazon", "apple", "microsoft", "paypal",
    "netflix", "instagram", "twitter", "linkedin", "whatsapp", "youtube", "yahoo", "ebay",
    "coinbase", "binance", "paytm", "phonepe", "hdfc", "icici", "sbi", "flipkart", "gpay", "bhim"];

const PRENAV_SUSP_TLDS = new Set(["xyz", "tk", "top", "cf", "ml", "ga", "gq", "pw", "cc",
    "icu", "club", "online", "site", "website", "space", "live", "click", "link", "info",
    "biz", "work", "store", "shop"]);

const PRENAV_FREE_KW = ["free", "prize", "winner", "claim", "giveaway", "bonus", "lucky", "congratulations"];
const PRENAV_FRAUD_KW = ["kyc", "verify", "update", "suspend", "block", "helpdesk", "refund", "tax-refund"];
const PRENAV_LOGIN_KW = ["login", "signin", "sign-in", "account", "verify", "auth", "confirm"];

function prenav_lev(a, b) {
    const m = a.length, n = b.length;
    let p = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
        const c = [i];
        for (let j = 1; j <= n; j++) {
            c[j] = Math.min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        }
        p = c;
    }
    return p[n];
}

function prenavScan(url) {
    let score = 0;
    const signals = [];
    const low = url.toLowerCase();

    let host = "", tld = "", domain = "", path = "", scheme = "";
    try {
        const u = new URL(url);
        host = u.hostname;
        path = u.pathname;
        tld = host.split(".").pop() || "";
        domain = host.split(".").slice(-2).join(".");
        scheme = u.protocol.replace(":", "");
    } catch { return { score: 0, signals: [], threatType: "Parse Error" }; }

    // Skip legitimate extension pages and local files
    if (scheme === "chrome" || scheme === "chrome-extension" ||
        scheme === "edge" || scheme === "about" || scheme === "file") {
        return { score: 0, signals: [], threatType: "Clean" };
    }

    // R1 — Punycode / IDN homograph
    if (host.includes("xn--")) { score += 0.9; signals.push("Punycode / IDN Homograph"); }
    // R2 — IP-in-URL
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { score += 0.85; signals.push("IP Address in URL"); }
    // R3 — Suspicious TLD
    if (PRENAV_SUSP_TLDS.has(tld)) { score += 0.55; signals.push(`Suspicious TLD (.${tld})`); }
    // R4 — Not HTTPS + login keywords
    if (scheme !== "https" && PRENAV_LOGIN_KW.some(k => low.includes(k))) { score += 0.6; signals.push("Login Page on HTTP"); }
    // R5 — Brand spoofing (Levenshtein ≤ 2)
    const core = (domain.split(".")[0] || "");
    const minD = Math.min(...PRENAV_BRANDS.map(b => prenav_lev(core, b)));
    if (minD > 0 && minD <= 2) { score += 0.8; signals.push(`Brand Spoof: "${core}"`); }
    // R6 — Multiple @ symbols
    if ((url.match(/@/g) || []).length > 1) { score += 0.8; signals.push("Multiple @ Symbols"); }
    // R7 — Excessive subdomains
    if (host.split(".").length >= 5) { score += 0.45; signals.push("Excessive Subdomain Depth"); }
    // R8 — Free/prize keywords
    if (PRENAV_FREE_KW.some(k => low.includes(k))) { score += 0.5; signals.push("Prize/Scam Keywords"); }
    // R9 — Fraud action keywords in domain/path
    if (PRENAV_FRAUD_KW.some(k => low.includes(k))) { score += 0.45; signals.push("Fraud Action Keywords"); }
    // R10 — Brand in subdomain but not registered domain
    const sub = host.split(".").slice(0, -2).join(".");
    const brandInSub = PRENAV_BRANDS.some(b => sub.includes(b));
    const brandInReg = PRENAV_BRANDS.some(b => core.includes(b));
    if (brandInSub && !brandInReg) { score += 0.85; signals.push("Brand Hijacked in Subdomain"); }
    // R11 — UPI fraud patterns
    if (/upi:\/\/pay|pa=.*@|vpa=/i.test(url)) { score += 0.6; signals.push("UPI Collect Request"); }
    // R12 — Executable in URL path  
    if (/\.(exe|scr|bat|ps1|vbs|cmd|msi)\b/i.test(path)) { score += 0.7; signals.push("Executable File in URL"); }

    const riskScore = Math.min(Math.round(score * 100), 100);
    let verdict = riskScore >= 50 ? "threat" : riskScore >= 30 ? "warning" : "safe";
    const threatType = signals.length ? signals[0] : "Clean";
    return { score: Math.min(score, 1.0), riskScore, signals, threatType, verdict };
}

// ── Rate limiting — prevent hammering notifications on fast navigations ────────
const recentlyScanned = new Map(); // url → timestamp
function isRateLimited(url) {
    const key = new URL(url).hostname;
    const now = Date.now();
    if (recentlyScanned.has(key) && (now - recentlyScanned.get(key)) < 10000) return true;
    recentlyScanned.set(key, now);
    if (recentlyScanned.size > 100) {
        const oldest = [...recentlyScanned.entries()].sort((a, b) => a[1] - b[1])[0][0];
        recentlyScanned.delete(oldest);
    }
    return false;
}

// ── The main pre-navigation hook (3-Stage Pipeline) ────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only scan main frame (frameId === 0), skip iframes
    if (details.frameId !== 0) return;

    const url = details.url;
    if (!url.startsWith("http://") && !url.startsWith("https://")) return;

    const settings = await getSettings();
    if (!settings.protection) return;

    // ── STAGE 1: Merkle Threat Vault — O(1) hash lookup (<0.1ms) ──────────────
    // Check if hostname SHA-256 is in confirmed-blocked Set.
    // If yes: instant block, skip all heuristics and ML entirely.
    let domain = "";
    try { domain = new URL(url).hostname.toLowerCase(); } catch { return; }

    const dHash = await sha256(domain);
    if (blockedDomainHashes.has(dHash)) {
        const params = new URLSearchParams({
            url: encodeURIComponent(url),
            risk: 100,
            threat: "Threat Vault: Previously Confirmed Blocked Domain",
            signals: encodeURIComponent("Merkle Vault match|SHA-256 domain hash confirmed"),
        });
        chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL(`block.html?${params}`) });
        // Badge only — no new vault entry needed (already recorded)
        chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: details.tabId });
        chrome.action.setBadgeText({ text: "✕", tabId: details.tabId });
        return;
    }

    // Rate-limit: don't re-run heuristics on same host within 10s
    if (isRateLimited(url)) return;

    // ── STAGE 2: Heuristic Pre-filter (<2ms) ──────────────────────────────────
    const result = prenavScan(url);
    result.layer = "heuristic";
    if (result.verdict === "safe") return;

    const hostname = (() => { try { return new URL(url).hostname; } catch { return url; } })();

    // ── WARNING: show OS notification ──────────────────────────────────────────
    if (result.verdict === "warning" && settings.notifications) {
        chrome.notifications.create(`bv-warn-${Date.now()}`, {
            type: "basic",
            iconUrl: "icons/icon48.png",
            title: "⚠ Browser Vigilant — Suspicious Site",
            message: `${result.threatType} detected on ${hostname}`,
            contextMessage: `Risk: ${result.riskScore}/100 · Proceed with caution`,
            priority: 1,
        });
        // Update badge
        chrome.action.setBadgeBackgroundColor({ color: "#f59e0b", tabId: details.tabId });
        chrome.action.setBadgeText({ text: "!", tabId: details.tabId });
        return;
    }

    // ── THREAT: block BEFORE page loads ───────────────────────────────────────
    if (result.verdict === "threat" && settings.autoBlock) {
        const params = new URLSearchParams({
            url: encodeURIComponent(url),
            risk: result.riskScore,
            threat: result.threatType,
            signals: encodeURIComponent(result.signals.slice(0, 5).join("|")),
        });
        const blockPageUrl = chrome.runtime.getURL(`block.html?${params.toString()}`);

        // Redirect to block page immediately
        chrome.tabs.update(details.tabId, { url: blockPageUrl });

        // Notify
        if (settings.notifications) {
            chrome.notifications.create(`bv-block-${Date.now()}`, {
                type: "basic",
                iconUrl: "icons/icon48.png",
                title: "🛡 Browser Vigilant — Site Blocked",
                message: `${result.threatType} on ${hostname}`,
                contextMessage: `Risk score: ${result.riskScore}/100 — Navigation cancelled`,
                priority: 2,
            });
        }

        // Record in history + Threat Vault (Merkle chain)
        await recordScan({
            url, status: "threat", scanMs: 0,
            riskScore: result.riskScore,
            signals: result.signals,
            threatType: result.threatType,
        });
        await updateStats(true);
        await appendChainBlock({
            url,
            threatType: result.threatType,
            signals: result.signals,
            riskScore: result.riskScore,
            layer: result.layer || "heuristic",
        });

        // Badge
        chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId: details.tabId });
        chrome.action.setBadgeText({ text: "✕", tabId: details.tabId });
    }
});

