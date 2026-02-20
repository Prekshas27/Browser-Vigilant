# Browser Vigilant v2.0 — Implementation Plan
## Real Cybersecurity · AI/ML · Blockchain · Zero Hardcoded Data

---

## 1. Problem Statement

Online phishing, UPI fraud, malicious file downloads, and credential-harvesting attacks cause billions in losses annually. Existing browser protections rely on:
- Cloud blacklists (slow, privacy-invasive, fail against zero-day domains)
- Simple regex rules (trivially bypassed)
- No file-level or payment-level awareness

**Browser Vigilant v2.0** solves this with a 5-layer, fully on-device, AI+blockchain-backed cybersecurity engine.

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    BROWSER VIGILANT v2.0                         │
│                                                                  │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────────────┐  │
│  │  content.js │───▶│ background.js│───▶│  Popup (Svelte)    │  │
│  │  (5 layers) │    │  (hub+store) │    │  Real data only    │  │
│  └──────┬──────┘    └──────┬───────┘    └────────────────────┘  │
│         │                  │                                      │
│   ┌─────▼──────────────────▼────────────────────────────────┐   │
│   │              DETECTION LAYERS                            │   │
│   │                                                          │   │
│   │  L1: Rust WASM Feature Extractor (48 real features)     │   │
│   │  L2: ONNX Ensemble ML Model (RF + GBM, trained on       │   │
│   │      11k+ real phishing/benign URLs)                     │   │
│   │  L3: Heuristic Rule Engine (Levenshtein, entropy,       │   │
│   │      punycode, TLD, UPI VPA patterns)                    │   │
│   │  L4: DOM Behavioral Analyzer (form harvesting, iframe   │   │
│   │      traps, fake login overlays, obfuscated scripts)    │   │
│   │  L5: Download/File Threat Interceptor (MIME mismatch,   │   │
│   │      double extension, filename entropy, VirusTotal-    │   │
│   │      style hash check via local bloom filter)           │   │
│   └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │   BLOCKCHAIN LEDGER (chrome.storage.local)               │   │
│   │   SHA-256 chained blocks · tamper-evident audit trail    │   │
│   └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. File Structure (Final)

```
Browser-Vigilant/
│
├── manifest.json                  # MV3 - full permissions
├── background.js                  # Service worker: storage, badges, download interception, messaging
├── content.js                     # Main detection engine (5 layers, injected into every page)
├── style.css                      # Minimal — injected alert banner styles only
├── block.html                     # Full-page block screen (standalone HTML)
│
├── ort.min.js                     # ONNX Runtime (already exists)
├── ort-wasm.wasm                  # Keep
├── ort-wasm-simd.wasm             # Keep
│
├── model/
│   ├── train.py                   # REAL training script (sklearn GBM + RF ensemble, 48 features)
│   ├── convert.py                 # Convert final ensemble to ONNX
│   ├── features.py                # Feature extraction helpers (shared between train and wasm)
│   ├── requirements.txt           # scikit-learn, skl2onnx, onnx, pandas, numpy
│   └── model.onnx                 # Output: trained & converted model
│
├── wasm-feature/
│   ├── src/lib.rs                 # 48-feature extractor (real math: entropy, Levenshtein, etc.)
│   └── Cargo.toml
│
├── wasm-build/                    # Build output from wasm-pack
│   ├── wasm_feature.js
│   └── wasm_feature_bg.wasm
│
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
│
└── popup/
    ├── index.html
    ├── vite.config.js
    ├── svelte.config.js
    ├── package.json
    └── src/
        ├── main.js
        ├── app.css                # Design tokens, typography
        ├── vite-env.d.ts
        ├── App.svelte             # Tab shell + real chrome.storage data loading
        └── components/
            ├── Shield.svelte      # Live scan status — real data via chrome.runtime.sendMessage
            ├── ThreatMap.svelte   # Replaces Blockchain.svelte — visual blockchain ledger
            ├── History.svelte     # Real scan history from chrome.storage.local
            └── Settings.svelte    # Real persisted settings via chrome.storage.sync
```

**Files to DELETE (unnecessary/unused):**
- `model/train_dummy.py` (replace with real `train.py`)
- `model/random_forest.pkl` (regenerated from real training)
- `popup/src/components/Blockchain.svelte` (renamed/replaced by ThreatMap.svelte)
- `wasm-build/` old outputs (rebuilt by wasm-pack)

---

## 4. Layer 1 — Rust WASM Feature Extractor (48 features)

**File:** `wasm-feature/src/lib.rs`

All features computed purely from the URL string using proper mathematical formulas. No hardcoded scores.

| # | Feature | Algorithm |
|---|---------|-----------|
| 0 | URL total length | `len(url)` |
| 1 | Domain length | Parse domain part |
| 2 | Path length | Parse path |
| 3 | Query string length | Parse query |
| 4 | Number of dots | `count('.')` |
| 5 | Number of hyphens | `count('-')` |
| 6 | Number of underscores | `count('_')` |
| 7 | Number of slashes | `count('/')` |
| 8 | Number of `@` symbols | `count('@')` |
| 9 | Number of digits | `count(is_digit)` |
| 10 | Digit ratio | `digits / len(url)` |
| 11 | HTTPS flag | `starts_with("https")` → 1/0 |
| 12 | IP address in URL | Regex: `\d{1,3}(\.\d{1,3}){3}` |
| 13 | Punycode detected | `xn--` in domain |
| 14 | Subdomain depth | `dots_in_domain - 1` |
| 15 | URL Shannon entropy | `H = -Σ p(c) log2 p(c)` over all chars |
| 16 | Domain Shannon entropy | Same formula applied to domain only |
| 17 | Path Shannon entropy | Applied to URL path |
| 18 | Suspicious TLD | Lookup against known bad TLD list (`.xyz`, `.tk`, `.top`, `.cf`, `.ml`, `.ga`, `.gq`) |
| 19 | Brand names in domain | Levenshtein distance ≤ 2 to top-50 brands |
| 20 | Levenshtein min distance | Min distance to brand list |
| 21 | Login keyword | `login`, `signin`, `account`, `verify`, `auth` in path/query |
| 22 | Secure keyword misuse | `secure`, `safe`, `trust`, `bank` in domain |
| 23 | Credential keyword | `password`, `passwd`, `pw`, `credential` in URL |
| 24 | Payment keyword | `pay`, `payment`, `wallet`, `upi`, `gpay`, `paytm`, `bhim` |
| 25 | Free keyword | `free`, `bonus`, `prize`, `winner`, `giveaway` |
| 26 | Hyphen in domain | Binary flag |
| 27 | Double extension | e.g. `.pdf.exe`, `.jpg.js` in path |
| 28 | Obfuscated URL | Percent-encoding ratio `%XX / len(url)` |
| 29 | Query param count | Count of `&` + 1 in query |
| 30 | Has port number | Explicit non-standard port in URL |
| 31 | Redirect chain depth | Count of `//` after protocol |
| 32 | Fragment presence | `#` in URL |
| 33 | Data URI | `data:` scheme |
| 34 | Path traversal | `../` or `..%2F` |
| 35 | Base64 in query | Detects base64-like strings in query params |
| 36 | Hex encoding ratio | Count of `%[0-9a-fA-F]{2}` patterns |
| 37 | TLD length | Length of top-level domain |
| 38 | Has subdomain | domain.split('.').len() > 2 |
| 39 | Domain is numeric | All domain chars are digits/dots |
| 40 | UPI VPA pattern | Matches `name@bankhandle` with suspicious handle |
| 41 | Known bad UPI handles | `@ybl`, `@okicici` etc. with suspicious prefix patterns |
| 42 | File extension risk | `.exe`, `.scr`, `.bat`, `.ps1`, `.vbs`, `.jar`, `.apk` |
| 43 | Short URL service | `bit.ly`, `tinyurl`, `t.co`, `goo.gl`, etc. |
| 44 | Brand in subdomain only | Brand name appears in subdomain but not in registered domain |
| 45 | URL compression ratio | `unique_chars / total_chars` (low = repetitive = suspicious) |
| 46 | Vowel ratio | Low vowel ratio in domain = gibberish domain heuristic |
| 47 | Consecutive consonants max | Max run of consonants (gibberish detection) |

**Rust dependencies:** `wasm-bindgen`, custom Levenshtein O(min(m,n)) implementation, Shannon entropy implementation.

---

## 5. Layer 2 — ML Ensemble Model

**File:** `model/train.py`

### Dataset
Use the **UCI Machine Learning Repository Phishing Dataset** features as the labeling scheme. The model trains on **computed features from real URLs** — not a static dataset download. We generate features from a curated list of known phishing and benign URLs (from open sources encoded directly in the script: PhishTank public data format + Alexa top sites format).

### Model Architecture
**Ensemble of two models converted to ONNX:**

```
Input: float32[1, 48]  (48 WASM-extracted features)
         │
    ┌────┴────┐
    │         │
   RF        GBM
(300 trees,  (GradientBoostingClassifier
 max_depth=8, n_estimators=200,
 min_samples=5) learning_rate=0.05,
    │         max_depth=5)
    └────┬────┘
         │  Soft voting (average probabilities)
         ▼
    Output: float32 probability [0.0 .. 1.0]
    Threshold: > 0.50 → THREAT
```

### Training parameters (real, not dummy):
```python
RandomForestClassifier(
    n_estimators=300,
    max_depth=8,
    min_samples_split=5,
    min_samples_leaf=2,
    max_features='sqrt',
    class_weight='balanced',     # handles imbalanced phishing/safe ratio
    random_state=42,
    n_jobs=-1
)

GradientBoostingClassifier(
    n_estimators=200,
    learning_rate=0.05,
    max_depth=5,
    min_samples_split=4,
    subsample=0.8,               # prevents overfitting
    max_features='sqrt',
    random_state=42
)
```

### Feature generation for training
Features are computed by a **pure Python mirror** of the Rust WASM extractor (`model/features.py`), applied to a URL corpus. This ensures features seen during training match features extracted at runtime exactly.

### ONNX Conversion
Both models exported via `skl2onnx` with `FloatTensorType([None, 48])`. Combined into a single averaged-probability ONNX pipeline.

---

## 6. Layer 3 — Heuristic Rule Engine

**Location:** Inside `content.js`, runs in parallel with ML.

Rules that fire independently (no ML needed), providing deterministic catches:

| Rule ID | Check | Method |
|---------|-------|--------|
| H1 | Punycode homograph | `xn--` prefix → immediate flag |
| H2 | IP-in-URL | IPv4 regex match on domain |
| H3 | Brand Levenshtein | JS Levenshtein(domain, top50brands) ≤ 1 |
| H4 | Suspicious TLD | Domain ends in `.xyz`, `.tk`, `.top`, etc. |
| H5 | Login page without HTTPS | `login`/`verify`/`account` on HTTP |
| H6 | UPI fraud pattern | VPA regex + suspicious handle prefix analysis |
| H7 | Free money keywords | Regex across full URL |
| H8 | Obfuscated redirect | `url=`, `redirect=`, `continue=` params encoding another URL |
| H9 | Data exfil form | Form action points to different domain than page |
| H10 | Multiple `@` in URL | Classic credential stuffing indicator |

Each triggered rule contributes an **additive risk score** (weighted by severity). Final heuristic score normalized 0→1.

---

## 7. Layer 4 — DOM Behavioral Analyzer

**Location:** Injected in `content.js` after `DOMContentLoaded`.

Scans the live DOM for behavioral red flags:

| Signal | What it checks | Risk Weight |
|--------|---------------|-------------|
| Fake login form | `<form>` with password field, action to external domain | HIGH |
| Invisible iframe | `<iframe>` with `display:none` or `width=0,height=0` | HIGH |
| Credential autofill bait | Hidden `<input type="password">` | MEDIUM |
| Obfuscated script | `<script>` with `eval(`, `atob(`, `unescape(` | HIGH |
| Fake captcha | Image claiming to be "CAPTCHA" on non-CAPTCHA domain | MEDIUM |
| DOM cloaking | `document.write()` replacing body on load | HIGH |
| Clipboard hijacking | `copy` event listener that replaces clipboard content | CRITICAL |
| Fake browser alert | `alert()/confirm()` called immediately on load | LOW |
| BeforeUnload trap | Page hooks `beforeunload` to prevent leaving | MEDIUM |
| External resource loading | Page loads resources from 5+ different origins | LOW |

MutationObserver watches for dynamically injected malicious DOM after load.

---

## 8. Layer 5 — File Download Interceptor

**Location:** `background.js` using `chrome.downloads.onDeterminingFilename`

Intercepts every file download and scores each:

| Check | Method | Action |
|-------|--------|--------|
| Dangerous extension | `.exe`, `.scr`, `.bat`, `.ps1`, `.vbs`, `.jar`, `.msi`, `.apk`, `.dmg`, `.cmd` | Auto-pause + warn |
| Double extension | `invoice.pdf.exe`, `photo.jpg.js` | Block |
| MIME mismatch | HTTP Content-Type vs actual file extension disagree | Block |
| Filename entropy | Shannon entropy of filename > 4.5 (gibberish name) | Warn |
| Misleading name | Filename contains brand name + executable extension | Block |
| Archive with script | `.zip` or `.rar` download from suspicious domain | Warn |

---

## 9. UPI / Payment Fraud Detection

**Location:** `content.js` + heuristic layer

Indian UPI VPA (Virtual Payment Address) format: `username@bankhandle`

**Detection logic:**
1. Scan DOM text and input fields for UPI VPA patterns using regex: `/[a-zA-Z0-9._-]+@[a-zA-Z]+/g`
2. Validate bank handle against **whitelist of legitimate NPCI-registered handles**: `@okaxis`, `@okicici`, `@oksbi`, `@okhdfcbank`, `@ybl`, `@ibl`, `@axl`, `@apl`, `@fbl`, `@rajgovhdfcbank`, `@paytm`, `@waaxis`, etc. (~60 registered handles)
3. Flag patterns with:
   - Unknown/unregistered bank handle
   - Handle that closely resembles (Levenshtein ≤ 1) a known handle but isn't exact
   - Username containing `refund`, `tax`, `prize`, `block`, `kyc`, `urgent`
   - QR codes on page that encode UPI URIs (`upi://pay?pa=...`) — parse and analyze
4. Detection of fake UPI collect requests (push payment fraud): DOM scan for payment request overlays

---

## 10. Blockchain Threat Ledger

**Location:** `background.js` + `chrome.storage.local`

Every blocked threat creates a **cryptographic chain entry** using the Web Crypto API (available in service workers).

### Block Structure
```javascript
{
  index: Number,
  timestamp: ISO8601 string,
  threatType: "PHISHING" | "MALWARE_DOWNLOAD" | "UPI_FRAUD" | "DOM_ATTACK" | "FILE_THREAT",
  url: String,
  signals: String[],           // Which rules/layers fired
  riskScore: Number (0-100),
  mlProbability: Number (0-1),
  heuristicScore: Number (0-1),
  domScore: Number (0-1),
  prevHash: SHA-256 hex string,
  hash: SHA-256 hex string,    // SHA-256(index + timestamp + url + signals + prevHash)
  nonce: Number                // For uniqueness
}
```

### Hash computation (real SHA-256 via Web Crypto API)
```javascript
async function hashBlock(block) {
  const data = `${block.index}${block.timestamp}${block.url}${block.prevHash}${block.nonce}`;
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}
```

### Tamper detection
On startup, `background.js` verifies the entire chain by recomputing each block's hash and checking `block[i].prevHash === block[i-1].hash`. If tampered, UI shows "LEDGER COMPROMISED" warning.

---

## 11. Popup UI — Real Data Architecture

**No hardcoded values. Data flows via `chrome.runtime.sendMessage`.**

### Data flow:
```
content.js detects threat
    → chrome.runtime.sendMessage({ type: 'SCAN_RESULT', data: {...} })
        → background.js receives, stores in chrome.storage.local, updates badge
            → popup opens → App.svelte queries chrome.runtime.sendMessage({ type: 'GET_STATE' })
                → background.js responds with live state from storage
```

### Popup tabs:
1. **Shield** — Current page scan result (pulled from storage for active tab's URL)
   - Shows live risk score, ML probability, per-signal breakdown
   - Threat DNA: bars with actual extracted feature values
   - No simulate buttons — shows real data only
   
2. **History** — Real scan log from `chrome.storage.local`
   - Paginated list of last 100 scanned URLs
   - Filters: All / Blocked / Safe / Warning
   - Export as JSON button
   
3. **Ledger** — Live blockchain visualization
   - Reads real chain from `chrome.storage.local`
   - Verifies integrity on render
   - Block explorer-style view
   
4. **Settings** — Persisted via `chrome.storage.sync`
   - Protection on/off
   - Auto-block threshold (0.5 / 0.7 / 0.9)
   - UPI fraud detection on/off
   - Download scanner on/off
   - DOM analysis on/off
   - Notification on/off
   - Clear history button

---

## 12. Build Steps (in order)

### Step 1: Train and export ML model
```bash
cd model
python -m venv venv
venv/Scripts/activate        # Windows
pip install -r requirements.txt
python train.py              # Outputs: model.onnx
```

### Step 2: Build WASM feature extractor
```bash
cd wasm-feature
wasm-pack build --target web --out-dir ../wasm-build
```

### Step 3: Build Svelte popup
```bash
cd popup
npm install
npm run build                # Outputs to ../dist-popup/
```

### Step 4: Load extension in Chrome
- Open `chrome://extensions`
- Enable Developer Mode
- Load Unpacked → select `Browser-Vigilant/` root directory

---

## 13. What gets REMOVED / CLEANED

| File | Status | Reason |
|------|--------|--------|
| `model/train_dummy.py` | **DELETE** | Dummy random data, replaced by real `train.py` |
| `model/random_forest.pkl` | **REGENERATE** | Comes from real training |
| `Blockchain.svelte` | **REPLACE** | Becomes `ThreatMap.svelte` with real ledger data |
| All hardcoded `history` arrays | **REMOVE** | Replaced by `chrome.storage.local` |
| All `simulateThreat()` / `simulateSafe()` buttons | **REMOVE** | No demo mode |
| Hardcoded signal values in Shield.svelte | **REMOVE** | Come from real extraction |
| `model/venv/` | **GITIGNORE** | Not committed |

---

## 14. Tech Stack Summary

| Component | Technology | Why |
|-----------|-----------|-----|
| Feature extraction | Rust → WASM | Zero-latency, sandboxed, <1MB |
| ML model | sklearn RF + GBM → ONNX | Industry-standard, runs on device |
| ONNX runtime | onnxruntime-web | Chrome MV3 compatible |
| Crypto hashing | Web Crypto API (SHA-256) | Native, no library needed |
| Storage | chrome.storage.local | Persistent, sandboxed |
| UI | Svelte 5 + Vite | Minimal bundle, reactive |
| UPI regex | RFC-compliant VPA parser | Validated against NPCI standards |
| Levenshtein | Wagner-Fischer O(m×n) | Exact edit distance |
| Shannon entropy | Σ -p·log₂(p) | Standard information theory |

---

## 15. Execution Order

1. ✅ Create `model/features.py` — shared Python feature extractor
2. ✅ Create `model/train.py` — real training with real URLs
3. ✅ Create `model/requirements.txt` — all dependencies
4. ✅ Rewrite `wasm-feature/src/lib.rs` — 48 real features with proper math
5. ✅ Rewrite `background.js` — storage hub, blockchain, download interception
6. ✅ Rewrite `content.js` — 5-layer detection engine
7. ✅ Create `block.html` — full-page block screen
8. ✅ Rewrite `popup/src/App.svelte` — real data loading
9. ✅ Rewrite `popup/src/components/Shield.svelte` — live signals from detection
10. ✅ Rewrite `popup/src/components/History.svelte` — chrome.storage history
11. ✅ Replace `Blockchain.svelte` → `ThreatMap.svelte` — live chain
12. ✅ Rewrite `popup/src/components/Settings.svelte` — persisted settings
13. ✅ Update `manifest.json` — correct permissions
14. ✅ Update `style.css` — minimal alert banner
15. ✅ Delete dummy files
