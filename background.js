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
    CHAIN: "bv_threat_chain",
    STATS: "bv_stats",
    SETTINGS: "bv_settings",
    TAB_STATE: "bv_tab_state",
};

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

const MAX_HISTORY = 200;

// ── Init ──────────────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async () => {
    const existing = await chrome.storage.local.get(KEYS.CHAIN);
    if (!existing[KEYS.CHAIN]) {
        const genesis = await buildGenesisBlock();
        await chrome.storage.local.set({
            [KEYS.CHAIN]: [genesis],
            [KEYS.HISTORY]: [],
            [KEYS.STATS]: { totalScanned: 0, totalBlocked: 0, threatsToday: 0, lastReset: todayDateStr() },
            [KEYS.TAB_STATE]: {},
        });
    }
    await ensureSettingsDefaults();
    console.log("[BV] Browser Vigilant v2.0 installed.");
});

chrome.runtime.onStartup.addListener(async () => {
    await resetDailyStatsIfNeeded();
    await verifyChainIntegrity();
    await ensureSettingsDefaults();
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
    const { chain } = await chrome.storage.local.get(KEYS.CHAIN);
    const prev = chain[chain.length - 1];
    const block = {
        index: prev.index + 1,
        timestamp: new Date().toISOString(),
        type: "THREAT_BLOCKED",
        url: threatData.url,
        threatType: threatData.threatType,
        signals: threatData.signals,
        riskScore: threatData.riskScore,
        mlProb: threatData.mlProb,
        hScore: threatData.hScore,
        domScore: threatData.domScore,
        prevHash: prev.hash,
        nonce: crypto.getRandomValues(new Uint32Array(1))[0],
    };
    block.hash = await hashBlock(block);
    chain.push(block);
    await chrome.storage.local.set({ [KEYS.CHAIN]: chain });
    return block;
}

async function verifyChainIntegrity() {
    const { [KEYS.CHAIN]: chain } = await chrome.storage.local.get(KEYS.CHAIN);
    if (!chain || chain.length === 0) return true;
    for (let i = 1; i < chain.length; i++) {
        const expected = await hashBlock({ ...chain[i], hash: undefined });
        if (chain[i].hash !== expected || chain[i].prevHash !== chain[i - 1].hash) {
            console.error(`[BV] Chain integrity FAILED at block ${i}`);
            await chrome.storage.local.set({ bv_chain_tampered: true });
            return false;
        }
    }
    await chrome.storage.local.set({ bv_chain_tampered: false });
    return true;
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
        const [tabState, settings, stats, history, chain, tampered] = await Promise.all([
            getTabState(tabId),
            getSettings(),
            chrome.storage.local.get(KEYS.STATS).then(r => r[KEYS.STATS]),
            chrome.storage.local.get(KEYS.HISTORY).then(r => r[KEYS.HISTORY] || []),
            chrome.storage.local.get(KEYS.CHAIN).then(r => r[KEYS.CHAIN] || []),
            chrome.storage.local.get("bv_chain_tampered").then(r => r.bv_chain_tampered || false),
        ]);
        return { tabState, settings, stats, history, chain, chainTampered: tampered };
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
