/**
 * content.js — Browser Vigilant Detection Engine (Layers 1–4)
 */

// ── Web Dashboard Bridge (PRIORITY) ──────────────────────────────────────────
let cachedSettings = null; // Local copy for instant allowlist checks

window.addEventListener("message", (event) => {
    if (!event.data || event.data.type !== "BV_WEB_REQUEST") return;

    const { action, settings } = event.data;

    // Cache settings locally if sent from dashboard
    if (action === "SAVE_SETTINGS" && settings) {
        cachedSettings = settings;
    }

    if (action === "GET_STATS") {
        try {
            chrome.runtime.sendMessage({ type: "GET_STATE" }, (response) => {
                if (chrome.runtime.lastError) return;
                if (response) {
                    if (response.settings) cachedSettings = response.settings;
                    window.postMessage({
                        type: "BV_WEB_RESPONSE",
                        action: "GET_STATS",
                        data: response
                    }, "*");
                }
            });
        } catch (e) { }
    }

    if (action === "SAVE_SETTINGS") {
        try {
            chrome.runtime.sendMessage({ type: "SAVE_SETTINGS", settings }, (response) => {
                if (chrome.runtime.lastError) return;
                window.postMessage({
                    type: "BV_WEB_RESPONSE",
                    action: "SAVE_SETTINGS",
                    success: response?.ack
                }, "*");
            });
        } catch (e) { }
    }
});

// ── Blockchain Threat Vault Integration ──────────────────────────────────────────
// Initialize blockchain components
let threatVault = null;
let isVaultInitialized = false;
let blockchainModules = null;

// Load blockchain dependencies first
async function loadBlockchainDependencies() {
    if (blockchainModules) return blockchainModules;

    try {
        // Load all blockchain modules
        const basePath = chrome.runtime.getURL('blockchain/');
        const [merkleModule, consensusModule, registryModule, vaultModule] = await Promise.all([
            import(basePath + 'merkle_tree.js'),
            import(basePath + 'federated_consensus.js'),
            import(basePath + 'threat_registry.js'),
            import(basePath + 'blockchain_vault.js')
        ]);

        blockchainModules = {
            MerkleTree: merkleModule.MerkleTree,
            FederatedConsensus: consensusModule.FederatedConsensus,
            ThreatRegistry: registryModule.ThreatRegistry,
            BlockchainThreatVault: vaultModule.BlockchainThreatVault
        };

        console.log('[Blockchain] Dependencies loaded successfully');
        return blockchainModules;
    } catch (error) {
        console.error('[Blockchain] Failed to load dependencies:', error);
        return null;
    }
}

async function initializeThreatVault() {
    if (isVaultInitialized) return;

    try {
        // Load dependencies first
        const modules = await loadBlockchainDependencies();
        if (!modules) {
            throw new Error('Failed to load blockchain dependencies');
        }

        // Create instances with proper dependencies
        const { BlockchainThreatVault, MerkleTree, FederatedConsensus, ThreatRegistry } = modules;

        // Initialize components in correct order
        const merkleTree = new MerkleTree();
        const consensus = new FederatedConsensus('browser-node-' + Date.now());
        const registry = new ThreatRegistry();

        // Create vault with dependencies
        threatVault = new BlockchainThreatVault(merkleTree, consensus, registry);
        await threatVault.initialize();
        isVaultInitialized = true;
        console.log('[Blockchain] Threat vault initialized successfully');
    } catch (error) {
        console.error('[Blockchain] Failed to initialize threat vault:', error);
        threatVault = null;
    }
}

// Enhanced threat checking with blockchain integration
async function checkThreatWithBlockchain(url) {
    if (!isVaultInitialized) {
        await initializeThreatVault();
    }

    if (threatVault) {
        try {
            const result = await threatVault.isThreat(url);
            if (result.isThreat) {
                return {
                    isThreat: true,
                    confidence: 0.99, // High confidence from blockchain
                    source: `blockchain_${result.source}`,
                    threatType: 'BLOCKCHAIN_CONFIRMED'
                };
            }
        } catch (error) {
            console.warn('[Blockchain] Check failed, falling back:', error);
        }
    }

    return null; // Fall back to traditional method
}

// Enhanced threat submission to blockchain
async function submitThreatToBlockchain(domain, confidence, threatType, evidence) {
    if (!isVaultInitialized) {
        await initializeThreatVault();
    }

    if (threatVault) {
        try {
            const result = await threatVault.submitThreat(domain, confidence, threatType, evidence);
            console.log(`[Blockchain] Threat submitted: ${domain}`);
            return result;
        } catch (error) {
            console.error(`[Blockchain] Failed to submit threat ${domain}:`, error);
        }
    }

    return null;
}

/**
 * Final verdict = weighted combination of all fired layers.
 * If verdict === "threat", page is replaced with block.html.
 */

(() => {
    "use strict";

    // Don't analyze extension pages, chrome:// pages, or blank pages
    const url = window.location.href;
    if (!url.startsWith("http://") && !url.startsWith("https://")) return;

    // Avoid double-injection
    if (window.__bvActive) return;
    window.__bvActive = true;

    // Check if the user explicitly allowed this page via the block screen
    if (new URL(window.location.href).searchParams.has("bv_allow")) {
        console.log("[BV] User bypassed protection for this session.");
        return;
    }

    const t0 = performance.now();

    // ── Constants ────────────────────────────────────────────────────────────────

    const BRANDS = [
        "google", "facebook", "amazon", "apple", "microsoft", "paypal", "netflix",
        "instagram", "twitter", "linkedin", "whatsapp", "youtube", "yahoo", "ebay",
        "dropbox", "spotify", "adobe", "chase", "wellsfargo", "bankofamerica",
        "citi", "hsbc", "barclays", "halifax", "natwest", "santander", "lloyds",
        "steam", "roblox", "epic", "coinbase", "binance", "metamask", "opensea",
        "paytm", "phonepe", "gpay", "bhim", "razorpay", "hdfc", "icici", "sbi",
        "axis", "kotak", "airtel", "jio", "vodafone", "bsnl", "flipkart", "myntra",
    ];

    // Trusted cross-domain services that legitimately use forms/iframes
    const TRUSTED_SERVICES = new Set([
        // Form services
        "forms.hsforms.com", "form.jotform.com", "form.typeform.com", "form.wufoo.com",
        "form.asana.com", "form.clickup.com", "form.airtable.com", "form.google.com",
        "form.microsoft.com", "form.salesforce.com", "form.hubspot.com",

        // Analytics/Tracking services
        "www.google-analytics.com", "analytics.google.com", "connect.facebook.net",
        "static.ads-twitter.com", "snap.licdn.com", "platform.twitter.com",
        "www.googletagmanager.com", "www.clarity.ms", "js.hs-scripts.com",

        // CDN/Static services
        "cdnjs.cloudflare.com", "unpkg.com", "cdn.jsdelivr.net", "ajax.googleapis.com",
        "code.jquery.com", "stackpath.bootstrapcdn.com", "use.fontawesome.com",

        // Payment services
        "checkout.stripe.com", "js.stripe.com", "pay.google.com", "apple-pay-gateway.apple.com",
        "api.paypal.com", "www.paypalobjects.com", "checkout.paypal.com",

        // Crypto services
        "widget.trustwallet.com", "cdn.live.ledger.com", "connect.trezor.io",
        "widget.cloud.coinbase.com", "pay.sendwyre.com", "api.ramp.network",

        // Authentication services
        "accounts.google.com", "login.microsoftonline.com", "auth0.com", "okta.com",
        "login.salesforce.com", "id.atlassian.com", "login.cloudflare.com"
    ]);

    // Trusted domain patterns (regex for subdomains)
    const TRUSTED_PATTERNS = [
        /\.cloudflare\.com$/,      // Cloudflare services
        /\.cloudfront\.net$/,      // AWS CloudFront
        /\.azureedge\.net$/,       // Azure CDN
        /\.fastly\.net$/,          // Fastly CDN
        /\.akamaihd\.net$/,        // Akamai
        /\.doubleclick\.net$/,     // Google advertising
        /\.googlesyndication\.com$/, // Google ads
        /\.googleusercontent\.com$/, // Google services
        /\.gstatic\.com$/,         // Google static
        /\.facebook\.com$/,        // Facebook services
        /\.fbcdn\.net$/,           // Facebook CDN
        /\.twitter\.com$/,         // Twitter services
        /\.twimg\.com$/,           // Twitter images
        /\.linkedin\.com$/,        // LinkedIn services
        /\.licdn\.com$/,           // LinkedIn CDN
        /\.youtube\.com$/,         // YouTube
        /\.ytimg\.com$/,           // YouTube images
        /\.github\.com$/,          // GitHub
        /\.githubusercontent\.com$/, // GitHub assets
        /\.npmjs\.org$/,           // NPM
        /\.jsdelivr\.net$/,        // jsDelivr CDN
        /\.unpkg\.com$/,           // unpkg CDN
    ];

    const SUSPICIOUS_TLDS = new Set([
        "xyz", "tk", "top", "cf", "ml", "ga", "gq", "pw", "cc", "icu", "club", "online",
        "site", "website", "space", "live", "click", "link", "info", "biz", "work",
        "tech", "store", "shop",
    ]);

    const LEGIT_UPI_HANDLES = new Set([
        "okaxis", "okicici", "oksbi", "okhdfcbank", "ybl", "ibl", "axl", "apl", "fbl",
        "upi", "paytm", "waaxis", "waxis", "rajgovhdfcbank", "barodampay", "allbank",
        "andb", "aubank", "cnrb", "csbpay", "dbs", "dcb", "federal", "hdfcbank", "idbi",
        "idfc", "indus", "idfcbank", "jio", "kotak", "lvb", "mahb", "nsdl", "pnb",
        "psb", "rbl", "sib", "tjsb", "uco", "union", "united", "vijb", "yapl", "airtel",
        "airtelpaymentsbank", "postbank",
    ]);

    const FRAUD_UPI_PREFIXES = new Set([
        "refund", "tax", "prize", "block", "kyc", "urgent", "helpdesk", "support",
        "care", "service", "verify", "government", "rbi", "sebi", "npci",
    ]);

    // ── Layer 3: Heuristic rule engine ───────────────────────────────────────────

    function Shannon(s) {
        if (!s) return 0;
        const freq = {};
        for (const c of s) freq[c] = (freq[c] || 0) + 1;
        const n = s.length;
        return -Object.values(freq).reduce((sum, f) => sum + (f / n) * Math.log2(f / n), 0);
    }

    function levenshtein(a, b) {
        const m = a.length, n = b.length;
        let prev = Array.from({ length: n + 1 }, (_, i) => i);
        for (let i = 1; i <= m; i++) {
            const curr = [i];
            for (let j = 1; j <= n; j++) {
                const cost = a[i - 1] === b[j - 1] ? 0 : 1;
                curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
            }
            prev = curr;
        }
        return prev[n];
    }

    function minBrandDistance(domain) {
        const core = (domain.split(".")[0] || "").toLowerCase();
        return Math.min(...BRANDS.map(b => levenshtein(core, b)));
    }

    function parseUrl(url) {
        try {
            const u = new URL(url);
            return {
                scheme: u.protocol.replace(":", ""),
                host: u.hostname,
                path: u.pathname,
                query: u.search.slice(1),
                hash: u.hash,
                port: u.port ? parseInt(u.port) : null,
                labels: u.hostname.split("."),
                tld: u.hostname.split(".").pop(),
                domain: u.hostname.split(".").slice(-2).join("."),
                sub: u.hostname.split(".").slice(0, -2).join("."),
            };
        } catch {
            return { scheme: "", host: url, path: "", query: "", hash: "", port: null, labels: [url], tld: "", domain: url, sub: "" };
        }
    }

    /**
     * Heuristic rule engine.
     * Returns { score: 0–1, signals: string[], triggered: RuleResult[] }
     */
    function runHeuristics(url) {
        const p = parseUrl(url);
        const low = url.toLowerCase();
        const signals = [];
        let score = 0;

        const rule = (id, label, weight, cond) => {
            if (cond) { score += weight; signals.push(label); }
        };

        // H1 — Punycode IDN homograph
        rule("H1", "Punycode/IDN Homograph", 0.9,
            p.host.includes("xn--"));

        // H2 — IP-in-URL
        rule("H2", "IP Address in URL", 0.85,
            /^\d{1,3}(\.\d{1,3}){3}$/.test(p.host));

        // H3 — Brand Levenshtein spoof (edit dist 1–2) WITH CONTEXT AWARENESS
        const bd = minBrandDistance(p.domain);
        // Additional context checks to reduce false positives
        const isCryptoContext = window.location.hostname.includes("wallet") ||
            window.location.hostname.includes("crypto") ||
            window.location.hostname.includes("blockchain") ||
            document.title.toLowerCase().includes("wallet") ||
            document.title.toLowerCase().includes("crypto");

        // For crypto-related sites, be more lenient with brand matching
        const brandThreshold = isCryptoContext ? 3 : 2; // Allow more distance for crypto sites

        // Check if this might be a legitimate service provider (e.g., metamask.io is legitimate)
        const isKnownLegit = BRANDS.some(b => p.host.includes(b)) ||
            TRUSTED_SERVICES.has(p.host) ||
            TRUSTED_PATTERNS.some(pattern => pattern.test(p.host));

        rule("H3", `Brand Spoof (edit-dist ${bd})`, isKnownLegit ? 0.2 : 0.8,
            bd > 0 && bd <= brandThreshold && !isKnownLegit);

        // H4 — Suspicious TLD
        rule("H4", `Suspicious TLD (.${p.tld})`, 0.6,
            SUSPICIOUS_TLDS.has(p.tld));

        // H5 — Login page without HTTPS
        const loginKw = ["login", "signin", "account", "verify", "auth", "confirm"];
        rule("H5", "Login Page on HTTP", 0.75,
            p.scheme !== "https" && loginKw.some(k => low.includes(k)));

        // H6 — Brand in subdomain, NOT in registered domain
        const brandInSub = BRANDS.some(b => p.sub.includes(b));
        const brandInReg = BRANDS.some(b => (p.domain.split(".")[0] || "").includes(b));
        rule("H6", "Brand Hijacked in Subdomain", 0.85,
            brandInSub && !brandInReg);

        // H7 — Excessive subdomains (depth ≥ 4)
        rule("H7", "Excessive Subdomain Depth", 0.5,
            p.labels.length >= 5);

        // H8 — Obfuscated redirect parameter
        const obfRedirect = /[?&](url|redirect|redir|continue|return|next|target|dest)=/i.test(url);
        rule("H8", "Encoded Redirect Parameter", 0.55,
            obfRedirect);

        // H9 — Multiple @ symbols (credential injection)
        rule("H9", "Multiple @ Symbols", 0.8,
            (url.match(/@/g) || []).length > 1);

        // H10 — Free/prize keywords
        const freeKw = ["free", "prize", "winner", "giveaway", "claim", "bonus", "lucky", "congratulation"];
        rule("H10", "Prize/Scam Keywords", 0.65,
            freeKw.some(k => low.includes(k)));

        // H11 — High URL entropy (characteristic of encoded/obfuscated phishing)
        const entropy = Shannon(url);
        rule("H11", `High URL Entropy (${entropy.toFixed(2)})`, 0.5,
            entropy > 5.2);

        // H12 — UPI VPA fraud detection
        const upiResult = analyzeUPI(url + " " + document.body?.innerText?.slice(0, 2000));
        if (upiResult.suspicious) {
            score += 0.85;
            signals.push(`UPI Fraud: ${upiResult.reason}`);
        }

        // Normalize score 0→1 (it can exceed 1 from multiple rules)
        return { score: Math.min(score, 1.0), signals };
    }

    // ── UPI Fraud Detection ───────────────────────────────────────────────────────

    function analyzeUPI(text) {
        // vpaPattern looks for prefix@handle, but ignores if the "handle" part looks like a full 
        // domain name with a TLD (e.g., @gmail.com) by ensuring no dot follows the handle immediately
        const vpaPattern = /([a-zA-Z0-9._-]+)@([a-zA-Z]+)(?!\.[a-zA-Z]{2,})/g;
        let match;
        while ((match = vpaPattern.exec(text)) !== null) {
            const prefix = match[1].toLowerCase();
            const handle = match[2].toLowerCase();

            // If the handle is too short or just weird, skip it
            if (handle.length < 2) continue;

            // Unknown handle
            if (!LEGIT_UPI_HANDLES.has(handle)) {
                // If it's an unknown handle, it's not immediately suspicious unless it's a known fraud prefix
                // to avoid false positives on random @mentions like @twitter
                let isFraudPfx = false;
                for (const fp of FRAUD_UPI_PREFIXES) {
                    if (prefix.includes(fp)) {
                        isFraudPfx = true; break;
                    }
                }
                if (isFraudPfx) {
                    return { suspicious: true, reason: `Fraudulent UPI prefix "${prefix}" on unknown handle @${handle}` };
                }
                continue; // otherwise just ignore non-whitelisted handles to prevent false positives
            }
            // Levenshtein spoof of a legit handle
            for (const legit of LEGIT_UPI_HANDLES) {
                const d = levenshtein(handle, legit);
                if (d > 0 && d <= 1) {
                    return { suspicious: true, reason: `Spoofed UPI handle @${handle} (near @${legit})` };
                }
            }
            // Fraud-indicating prefix
            for (const fp of FRAUD_UPI_PREFIXES) {
                if (prefix.includes(fp)) {
                    return { suspicious: true, reason: `Fraudulent UPI prefix "${prefix}"` };
                }
            }
        }
        // Scan for UPI pay URIs (upi://pay?pa=...)
        const upiUriPattern = /upi:\/\/pay\?.*?pa=([^&\s]+)/gi;
        while ((match = upiUriPattern.exec(text)) !== null) {
            const vpa = match[1];
            const [pfx, hdl] = vpa.split("@");
            if (!hdl || !LEGIT_UPI_HANDLES.has(hdl.toLowerCase())) {
                return { suspicious: true, reason: `Suspicious UPI URI: ${vpa}` };
            }
            if (pfx && [...FRAUD_UPI_PREFIXES].some(fp => pfx.toLowerCase().includes(fp))) {
                return { suspicious: true, reason: `Fraud UPI collect request: ${vpa}` };
            }
        }
        return { suspicious: false };
    }

    // ── Layer 4: DOM Behavioral Analysis ─────────────────────────────────────────

    function analyzeDom() {
        let score = 0;
        const signals = [];

        const rule = (label, weight, cond) => {
            if (cond) { score += weight; signals.push(label); }
        };

        // D1 — Password input field on HTTP
        const hasPasswordField = document.querySelector('input[type="password"]') !== null;
        rule("Password Form on HTTP", 0.7,
            hasPasswordField && window.location.protocol !== "https:");

        // D2 — Form action pointing to different domain (INTELLIGENT VERSION)
        document.querySelectorAll("form").forEach(form => {
            const action = form.getAttribute("action") || "";
            if (action.startsWith("http") || action.startsWith("//")) {
                try {
                    const actionHost = new URL(action, window.location.href).hostname;
                    if (actionHost && actionHost !== window.location.hostname) {
                        // Check if the target domain is trusted
                        const isTrusted = TRUSTED_SERVICES.has(actionHost) ||
                            TRUSTED_PATTERNS.some(pattern => pattern.test(actionHost));

                        if (!isTrusted) {
                            // Only flag if it's not a known legitimate service
                            // Reduced weight from 0.8 to 0.3 for legitimate cross-domain forms
                            score += 0.3;
                            signals.push(`Cross-Domain Form Action → ${actionHost} (untrusted)`);
                        } else {
                            // Trusted service - very low weight or none
                            signals.push(`Cross-Domain Form Action → ${actionHost} (trusted service)`);
                        }
                    }
                } catch { }
            }
        });

        // D3 — Invisible iframes (INTELLIGENT VERSION - context-aware)
        let hiddenIframeCount = 0;
        let suspiciousIframes = 0;
        document.querySelectorAll("iframe").forEach(iframe => {
            const style = window.getComputedStyle(iframe);
            const w = parseFloat(style.width || "0");
            const h = parseFloat(style.height || "0");
            const src = iframe.src || "";

            // Check if iframe source is from a trusted service
            let isTrustedSource = false;
            try {
                if (src) {
                    const iframeHost = new URL(src, window.location.href).hostname;
                    isTrustedSource = TRUSTED_SERVICES.has(iframeHost) ||
                        TRUSTED_PATTERNS.some(pattern => pattern.test(iframeHost));
                }
            } catch { }

            // Count hidden iframes
            if (style.display === "none" || style.visibility === "hidden" || w < 2 || h < 2) {
                hiddenIframeCount++;
                // Only count as suspicious if it's NOT from a trusted source
                if (!isTrustedSource) {
                    suspiciousIframes++;
                }
            }
        });

        // Weight based on suspicious vs total iframes
        if (suspiciousIframes > 0) {
            // Reduced from 0.15 to 0.1, and scaled by suspicious ratio
            const weight = Math.min(0.1 * (suspiciousIframes / Math.max(1, hiddenIframeCount)), 0.3);
            rule("Suspicious Hidden Iframe Detected", weight, suspiciousIframes > 0);
        }

        // Log trusted iframes for transparency
        if (hiddenIframeCount > suspiciousIframes) {
            signals.push(`${hiddenIframeCount - suspiciousIframes} trusted hidden iframes detected`);
        }

        // D4 — Obfuscated scripts (eval, atob, unescape — characteristic of malware)
        let hasObfScript = false;
        document.querySelectorAll("script:not([src])").forEach(script => {
            const src = script.textContent || "";
            if (/\beval\s*\(|\batob\s*\(|\bunescape\s*\(|\bString\.fromCharCode/i.test(src)) {
                hasObfScript = true;
            }
        });
        rule("Obfuscated Script Detected", 0.2, hasObfScript);

        // D5 — Clipboard hijacking (copy event listener replacing clipboard)
        // Check for event listeners on window for 'copy' (heuristic: check page scripts)
        const allScriptText = Array.from(document.querySelectorAll("script:not([src])"))
            .map(s => s.textContent).join(" ");
        rule("Clipboard/Polyfill Script", 0.15,
            /addEventListener\s*\(\s*['"]copy['"]/i.test(allScriptText) &&
            /clipboardData|getSelection/i.test(allScriptText));

        // D6 — BeforeUnload trap (prevents user from leaving)
        rule("BeforeUnload Exit Trap", 0.4,
            /addEventListener\s*\(\s*['"]beforeunload['"]/i.test(allScriptText));

        // D7 — Fake loading overlay with credential fields
        const overlays = document.querySelectorAll('[style*="position:fixed"],[style*="position: fixed"]');
        let hasCredOverlay = false;
        overlays.forEach(el => {
            if (el.querySelector('input[type="password"]') || el.querySelector('input[type="email"]')) {
                hasCredOverlay = true;
            }
        });
        rule("Fake Credential Overlay", 0.9, hasCredOverlay);

        // D8 — Data URI in iframes or anchor href
        const dataUriElements = document.querySelectorAll('[src^="data:text"],[href^="data:text"]');
        rule("Data URI Injection", 0.2, dataUriElements.length > 0);

        // D9 — Excessive external resource origins (data exfiltration)
        const resourceOrigins = new Set();
        document.querySelectorAll("script[src]").forEach(s => {
            try { resourceOrigins.add(new URL(s.src, window.location.href).hostname); } catch { }
        });
        rule("Excessive External Script Origins", 0.2, resourceOrigins.size > 8);

        // D10 — Fake CAPTCHA (image with captcha-related alt/class on non-standard domain)
        const fakeCapt = document.querySelectorAll('img[alt*="captcha" i],[class*="captcha" i]');
        const legitimateCaptchaDomains = ["recaptcha.net", "hcaptcha.com", "cloudflare.com"];
        if (fakeCapt.length > 0) {
            const isReal = legitimateCaptchaDomains.some(d => window.location.hostname.includes(d));
            rule("Fake CAPTCHA Element", 0.55, !isReal);
        }

        return { score: Math.min(score, 1.0), signals };
    }

    // ── Layer 1+2: WASM + ONNX inference ─────────────────────────────────────────

    async function runWasmAndML(url) {
        let mlProb = null;
        let features = null;

        try {
            // Wait for WASM to be ready via our loader
            const maxWait = 3000; // Reduced wait time
            const startTime = Date.now();

            // Wait for wasm-loader to initialize
            while (!window.wasmFeatureExtractor && (Date.now() - startTime) < maxWait) {
                await new Promise(resolve => setTimeout(resolve, 50));
            }

            // Use fallback if WASM not available
            if (!window.wasmFeatureExtractor || !window.wasmFeatureExtractor.extract_features) {
                console.warn('[BV] WASM not available, using basic feature extraction');
                // Use a simple stub for features if fallback fails
                features = new Array(56).fill(0);
                features[0] = url.length;

            } else {
                // Extract features using WASM
                features = window.wasmFeatureExtractor.extract_features(url);
            }

            if (!features && window.wasm_bindgen && typeof window.wasm_bindgen.extract_features === 'function') {
                features = Array.from(window.wasm_bindgen.extract_features(url));
            }

            // Layer 2: ONNX ML inference
            // Disable threading + JSEP — only basic ort-wasm.wasm or ort-wasm-simd.wasm exist
            ort.env.wasm.numThreads = 1;     // stops ORT from loading *-threaded.jsep.mjs
            ort.env.wasm.simd = false;  // disable simd to avoid any SIMD web worker loading issues completely
            ort.env.workers = 0;
            ort.env.wasm.proxy = false; // no web worker proxy
            // Configure ONNX Runtime for extension environment
            ort.env.wasm.numThreads = 1;     // disable threading to avoid loading threaded modules
            ort.env.wasm.simd = false;       // force disable SIMD to avoid loading separate .wasm files that fail in extension context
            ort.env.wasm.wasmPaths = {
                'ort-wasm.wasm': chrome.runtime.getURL('ort-wasm.wasm'),
            };
            // Explicitly prevent search for other wasm files
            ort.env.wasm.proxy = false;
            ort.env.workers = 0;
            // Remove any corejs paths that might cause issues
            ort.env.wasm.wasmCorejsPaths = undefined;
            if (ort.env.wasm.corejs) ort.env.wasm.corejs = undefined;

            const modelUrl = chrome.runtime.getURL("model.onnx");
            const session = await ort.InferenceSession.create(modelUrl, {
                executionProviders: ["wasm"],
                graphOptimizationLevel: "basic",
                enableMemPattern: false,
                enableCpuMemArena: false,
                extraOptions: {
                    session: {
                        intra_op_num_threads: 1,
                        inter_op_num_threads: 1,
                        use_deterministic_compute: 1
                    }
                }
            });
            const tensor = new ort.Tensor("float32", Float32Array.from(features), [1, 56]);
            const results = await session.run({ input: tensor });

            // Extract phishing probability from model outputs
            const probTensor = results.output_probability || results.probabilities || results.output_probabilities;
            if (probTensor) {
                const data = probTensor.data;
                mlProb = data.length >= 2 ? data[1] : data[0];
            } else {
                const label = results.output_label || results.label;
                mlProb = label ? (Number(label.data[0]) === 1 ? 0.9 : 0.1) : 0.1;
            }
        } catch (e) {
            console.warn("[BV] WASM/ML layer failed (heuristics still active):", e.message);
        }

        return { mlProb, features };
    }

    // ── Verdict engine ────────────────────────────────────────────────────────────

    function computeFinalVerdict(mlProb, heuristicResult, domResult, settings, isWhitelisted = false) {
        if (isWhitelisted) {
            return { verdict: "safe", riskScore: 0, composite: 0, hardTriggered: false };
        }

        // Weights: ML is primary, heuristics and DOM supplement
        // REDUCED weights to prevent false positives
        const mlWeight = 0.65;      // Increased from 0.55
        const hWeight = 0.25;       // Reduced from 0.30
        const domWeight = 0.10;     // Reduced from 0.15

        let composite = 0;
        let usedLayers = 0;

        if (mlProb !== null) {
            composite += mlProb * mlWeight;
            usedLayers++;
        }
        composite += heuristicResult.score * hWeight;
        composite += domResult.score * domWeight;

        // Hard rules: certain heuristics override regardless of ML
        const HARD_BLOCK_SIGNALS = [
            "Punycode/IDN Homograph",
            "Brand Hijacked in Subdomain",
            "Multiple @ Symbols",
            "Fake Credential Overlay",
            "Clipboard Hijacking Script",
        ];
        const allSignals = [...heuristicResult.signals, ...domResult.signals];
        const hardTriggered = allSignals.some(s => HARD_BLOCK_SIGNALS.some(hb => s.includes(hb)));

        // INCREASED thresholds to prevent false positives
        const threshold = settings?.blockThreshold ?? 0.65;  // Increased from 0.50
        const strictMode = settings?.strictMode ?? false;
        const effectiveThreshold = strictMode ? 0.50 : threshold; // Increased from 0.35

        let verdict;
        if (hardTriggered || composite >= effectiveThreshold) {
            verdict = "threat";
        } else if (composite >= effectiveThreshold * 0.5) {  // Reduced from 0.6
            verdict = "warning";
        } else {
            verdict = "safe";
        }

        return {
            verdict,
            riskScore: Math.round(composite * 100),
            composite,
            hardTriggered,
        };
    }

    // ── Blocking ──────────────────────────────────────────────────────────────────

    function blockPage(threatType, riskScore, signals) {
        // --- EMERGENCY ALLOWLIST BYPASS ---
        const domain = window.location.hostname.toLowerCase();
        const allowed = cachedSettings?.allowlist || [];
        if (allowed.some(d => domain === d.trim().toLowerCase() || domain.endsWith("." + d.trim().toLowerCase()))) {
            console.log(`[BV] Emergency Bypass: ${domain} is allowlisted. Navigation allowed.`);
            return;
        }

        const blockUrl = chrome.runtime.getURL("block.html");
        const params = new URLSearchParams({
            url: encodeURIComponent(window.location.href),
            risk: riskScore,
            threat: threatType,
            signals: encodeURIComponent(signals.slice(0, 5).join("|")),
        });
        window.location.replace(`${blockUrl}?${params.toString()}`);
    }

    // ── Main execution ────────────────────────────────────────────────────────────

    async function executeVigilant() {
        const t0 = performance.now();
        const url = window.location.href;

        // --- LOAD SETTINGS FIRST ---
        let settings = cachedSettings || { protection: true, domAnalysis: true, autoBlock: true, allowlist: [] };

        // Always try to get most fresh state from background too
        try {
            const state = await chrome.runtime.sendMessage({ type: "GET_STATE" });
            if (state && state.settings) {
                settings = state.settings;
                cachedSettings = settings; // Update cache
            }
        } catch {
            console.warn("[BV] Background sync delayed, using cache.");
        }

        if (settings.protection === false) return;

        // --- LAYER 0: ALLOWLIST (Highest Priority) ---
        const currentDomain = window.location.hostname.toLowerCase();
        const allowed = settings.allowlist || [];
        if (allowed.some(d => currentDomain === d.trim().toLowerCase() || currentDomain.endsWith("." + d.trim().toLowerCase()))) {
            console.log(`[BV] Allowlisted domain: ${currentDomain}. Skipping all checks.`);
            return;
        }

        // --- LAYER 1: Blockchain Threat Vault Check ---
        try {
            const blockchainResult = await checkThreatWithBlockchain(url);
            if (blockchainResult && blockchainResult.isThreat) {
                blockPage(blockchainResult.threatType, 99, [`Blockchain verified threat: ${blockchainResult.source}`]);
                return;
            }
        } catch (error) {
            console.warn('[Blockchain] Check failed, continuing...', error);
        }

        // (Blockchain check completed above, now proceed with heuristics and ML)

        // Layer 3: Heuristics (fast, synchronous)
        const hResult = runHeuristics(url);

        // Layer 4: DOM analysis (runs immediately if DOM is ready)
        let domResult = { score: 0, signals: [] };
        if (settings.domAnalysis !== false) {
            if (document.readyState === "loading") {
                await new Promise(r => document.addEventListener("DOMContentLoaded", r, { once: true }));
            }
            domResult = analyzeDom();
            // Also set up MutationObserver for dynamic DOM threats
            setupMutationObserver(domResult);
        }

        // Early exit for definite hard-rule threats (no need to wait for ML)
        const INSTANT_BLOCK = [
            "Punycode/IDN Homograph", "Brand Hijacked in Subdomain",
            "Multiple @ Symbols", "Fake Credential Overlay",
        ];

        // Critical Whitelist: Never hard-block trusted essential domains based on heuristics alone
        const SAFE_DOMAINS = [
            "google.com", "youtube.com", "github.com", "microsoft.com", "apple.com",
            "metamask.io", "support.metamask.io", "coinbase.com", "binance.com",
            "opensea.io", "trustwallet.com", "ledger.com", "trezor.io"
        ];

        // Extended trusted domains with patterns
        const TRUSTED_DOMAIN_PATTERNS = [
            /\.github\.io$/,           // GitHub Pages
            /\.vercel\.app$/,          // Vercel deployments
            /\.netlify\.app$/,         // Netlify deployments
            /\.surge\.sh$/,            // Surge.sh
            /\.firebaseapp\.com$/,     // Firebase
            /\.web\.app$/,             // Firebase hosting
            /\.onrender\.com$/,        // Render.com
            /\.railway\.app$/,         // Railway
            /\.fly\.dev$/,             // Fly.io
            /\.herokuapp\.com$/,       // Heroku
            /\.pages\.dev$/,           // Cloudflare Pages
            /\.workers\.dev$/,         // Cloudflare Workers
        ];

        const isWhitelisted = SAFE_DOMAINS.some(d =>
            window.location.hostname === d || window.location.hostname.endsWith("." + d)
        ) || TRUSTED_DOMAIN_PATTERNS.some(pattern => pattern.test(window.location.hostname));

        let hasInstantBlock = false;
        if (!isWhitelisted) {
            hasInstantBlock = [...hResult.signals, ...domResult.signals]
                .some(s => INSTANT_BLOCK.some(ib => s.includes(ib)));
        }

        // Layers 1+2: WASM + ONNX (async)
        const { mlProb, features } = await runWasmAndML(url);

        const scanMs = +(performance.now() - t0).toFixed(1);
        const verdictResult = computeFinalVerdict(mlProb, hResult, domResult, settings, isWhitelisted);
        const allSignals = [...hResult.signals, ...domResult.signals];

        // Determine threat type label
        const threatType = determineThreatType(hResult.signals, domResult.signals, mlProb);

        const result = {
            url: url,
            verdict: verdictResult.verdict,
            riskScore: verdictResult.riskScore,
            mlProb: mlProb !== null ? +mlProb.toFixed(3) : null,
            hScore: +hResult.score.toFixed(3),
            domScore: +domResult.score.toFixed(3),
            signals: allSignals,
            threatType: threatType,
            scanMs: scanMs,
            features: features?.slice(0, 10),  // send first 10 features to popup for display
        };

        // Report to background
        try {
            const tabs = await new Promise(r => chrome.tabs.getCurrent(r));
            await chrome.runtime.sendMessage({
                type: "SCAN_RESULT",
                result,
                tabId: tabs?.id,
            });
        } catch { }

        // Block if threat and auto-block is enabled
        if (verdictResult.verdict === "threat" && settings.autoBlock !== false) {
            // Submit high-confidence threats to blockchain for network validation
            if (verdictResult.composite >= 0.8) {
                try {
                    const threatType = determineThreatType(hResult.signals, domResult.signals, mlProb);
                    const evidence = {
                        url: window.location.href,
                        features: features,
                        heuristicSignals: hResult.signals,
                        domSignals: domResult.signals,
                        mlConfidence: mlProb,
                        compositeScore: verdictResult.composite
                    };

                    await submitThreatToBlockchain(
                        window.location.hostname,
                        verdictResult.composite,
                        threatType,
                        evidence
                    );
                } catch (error) {
                    console.warn('[Blockchain] Failed to submit threat:', error);
                }
            }

            blockPage(threatType, verdictResult.riskScore, allSignals);
        }
    }

    function determineThreatType(hSignals, dSignals, mlProb) {
        const all = [...hSignals, ...dSignals].join(" ").toLowerCase();
        if (all.includes("upi") || all.includes("vpa")) return "UPI Fraud";
        if (all.includes("punycode") || all.includes("homograph")) return "IDN Homograph Attack";
        if (all.includes("brand spoof") || all.includes("brand hijack")) return "Brand Spoofing";
        if (all.includes("credential") || all.includes("password")) return "Credential Harvesting";
        if (all.includes("clipboard")) return "Clipboard Hijacking";
        if (all.includes("ip address")) return "IP-Based Phishing";
        if (all.includes("redirect")) return "Redirect-Based Phishing";
        if (all.includes("suspicious tld")) return "Suspicious Domain";
        if (mlProb !== null && mlProb > 0.7) return "ML-Detected Phishing";
        return "Multi-Signal Threat";
    }

    // ── MutationObserver for dynamic DOM threats ──────────────────────────────────

    function setupMutationObserver(initialDomResult) {
        let debounceTimer = null;
        const observer = new MutationObserver(() => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(async () => {
                const freshDom = analyzeDom();
                if (freshDom.score > initialDomResult.score + 0.3) {
                    // Significant new threat appeared in DOM
                    const settings = {};
                    const tabs = await new Promise(r => chrome.tabs.getCurrent(r)).catch(() => null);
                    if (tabs) {
                        const state = await chrome.runtime.sendMessage({ type: "GET_STATE", tabId: tabs.id }).catch(() => ({}));
                        Object.assign(settings, state?.settings || {});
                    }
                    if (freshDom.score >= 0.6 && settings.autoBlock !== false) {
                        blockPage("DOM Behavioral Threat", Math.round(freshDom.score * 100), freshDom.signals);
                    }
                }
            }, 1500);
        });
        observer.observe(document.body || document.documentElement, {
            childList: true, subtree: true, attributes: false,
        });
    }

    // ── Boot ──────────────────────────────────────────────────────────────────────
    executeVigilant().catch(e => console.warn("[BV] Engine error:", e));
})();
