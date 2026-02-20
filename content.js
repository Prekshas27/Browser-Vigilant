/**
 * content.js — Browser Vigilant Detection Engine (Layers 1–4)
 *
 * Layer 1: 48-feature URL extraction via Rust WASM
 * Layer 2: ONNX ML ensemble inference (RF + GBM soft-vote)
 * Layer 3: Heuristic rule engine (Levenshtein, punycode, TLD, UPI)
 * Layer 4: DOM behavioral analysis (forms, iframes, obfuscated scripts)
 *
 * Layer 5 (file downloads) is handled by background.js.
 *
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

        // H3 — Brand Levenshtein spoof (edit dist 1–2)
        const bd = minBrandDistance(p.domain);
        rule("H3", `Brand Spoof (edit-dist ${bd})`, 0.8,
            bd > 0 && bd <= 2);

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
        const vpaPattern = /([a-zA-Z0-9._-]+)@([a-zA-Z]+)/g;
        let match;
        while ((match = vpaPattern.exec(text)) !== null) {
            const prefix = match[1].toLowerCase();
            const handle = match[2].toLowerCase();
            // Unknown handle
            if (!LEGIT_UPI_HANDLES.has(handle)) {
                return { suspicious: true, reason: `Unknown UPI handle @${handle}` };
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

        // D2 — Form action pointing to different domain
        document.querySelectorAll("form").forEach(form => {
            const action = form.getAttribute("action") || "";
            if (action.startsWith("http") || action.startsWith("//")) {
                try {
                    const actionHost = new URL(action, window.location.href).hostname;
                    if (actionHost && actionHost !== window.location.hostname) {
                        score += 0.8;
                        signals.push(`Cross-Domain Form Action → ${actionHost}`);
                    }
                } catch { }
            }
        });

        // D3 — Invisible iframes (credential overlay / clickjacking)
        document.querySelectorAll("iframe").forEach(iframe => {
            const style = window.getComputedStyle(iframe);
            const w = parseFloat(style.width || "0");
            const h = parseFloat(style.height || "0");
            const hidden = style.display === "none" || style.visibility === "hidden" || w < 2 || h < 2;
            rule("Hidden Iframe Detected", 0.7, hidden);
        });

        // D4 — Obfuscated scripts (eval, atob, unescape — characteristic of malware)
        document.querySelectorAll("script:not([src])").forEach(script => {
            const src = script.textContent || "";
            const obf = /\beval\s*\(|\batob\s*\(|\bunescape\s*\(|\bString\.fromCharCode/i.test(src);
            rule("Obfuscated Script Detected", 0.75, obf);
        });

        // D5 — Clipboard hijacking (copy event listener replacing clipboard)
        // Check for event listeners on window for 'copy' (heuristic: check page scripts)
        const allScriptText = Array.from(document.querySelectorAll("script:not([src])"))
            .map(s => s.textContent).join(" ");
        rule("Clipboard Hijacking Script", 0.85,
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
        rule("Data URI Injection", 0.75, dataUriElements.length > 0);

        // D9 — Excessive external resource origins (data exfiltration)
        const resourceOrigins = new Set();
        document.querySelectorAll("script[src]").forEach(s => {
            try { resourceOrigins.add(new URL(s.src, window.location.href).hostname); } catch { }
        });
        rule("Excessive External Script Origins", 0.4, resourceOrigins.size > 8);

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
            // Layer 1: Load Rust WASM module
            const wasmJsPath = chrome.runtime.getURL("wasm-build/wasm_feature.js");
            const { default: initWasm, extract_features } = await import(wasmJsPath);
            const wasmBinaryPath = chrome.runtime.getURL("wasm-build/wasm_feature_bg.wasm");

            // NEW wasm-bindgen API: pass object, not bare string
            await initWasm({ module_or_path: fetch(wasmBinaryPath) });
            features = Array.from(extract_features(url));

            // Layer 2: ONNX ML inference
            // Disable threading + JSEP — only basic ort-wasm.wasm or ort-wasm-simd.wasm exist
            ort.env.wasm.numThreads = 1;     // stops ORT from loading *-threaded.jsep.mjs
            ort.env.wasm.simd = true;  // use SIMD if available
            ort.env.wasm.proxy = false; // no web worker proxy
            ort.env.wasm.wasmPaths = {
                'ort-wasm.wasm': chrome.runtime.getURL('ort-wasm.wasm'),
                'ort-wasm-simd.wasm': chrome.runtime.getURL('ort-wasm-simd.wasm'),
                // Fallback: if only basic wasm exists, map simd → basic
            };

            const modelUrl = chrome.runtime.getURL("model/model.onnx");
            const session = await ort.InferenceSession.create(modelUrl, {
                executionProviders: ["wasm"],
                graphOptimizationLevel: "basic",
            });
            const tensor = new ort.Tensor("float32", Float32Array.from(features), [1, 48]);
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

    function computeFinalVerdict(mlProb, heuristicResult, domResult, settings) {
        // Weights: ML is primary, heuristics and DOM supplement
        const mlWeight = 0.55;
        const hWeight = 0.30;
        const domWeight = 0.15;

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

        const threshold = settings?.blockThreshold ?? 0.50;
        const strictMode = settings?.strictMode ?? false;
        const effectiveThreshold = strictMode ? 0.35 : threshold;

        let verdict;
        if (hardTriggered || composite >= effectiveThreshold) {
            verdict = "threat";
        } else if (composite >= effectiveThreshold * 0.6) {
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
        // Get settings from background
        let settings = {};
        try {
            const tabs = await new Promise(r => chrome.tabs.getCurrent(r));
            const state = await chrome.runtime.sendMessage({
                type: "GET_STATE",
                tabId: tabs?.id,
            });
            settings = state?.settings || {};
        } catch { }

        if (settings.protection === false) return;

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
        const hasInstantBlock = [...hResult.signals, ...domResult.signals]
            .some(s => INSTANT_BLOCK.some(ib => s.includes(ib)));

        // Layers 1+2: WASM + ONNX (async)
        const { mlProb, features } = await runWasmAndML(url);

        const scanMs = +(performance.now() - t0).toFixed(1);
        const verdictResult = computeFinalVerdict(mlProb, hResult, domResult, settings);
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
