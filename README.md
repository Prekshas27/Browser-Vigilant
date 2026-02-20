# 🛡 Browser Vigilant v2.0

> **Multi-layer AI cybersecurity browser extension** — 100% on-device. Blocks phishing, UPI fraud, malicious downloads, and DOM attacks *before* pages even load.

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![MV3](https://img.shields.io/badge/Manifest-V3-green)
![License](https://img.shields.io/badge/license-MIT-purple)

---

## ✨ Features

| Layer | Technology | What it does |
|-------|-----------|--------------|
| **Pre-Navigation Scanner** | Background JS · Levenshtein | Scans URL *before* page loads → OS notification or block |
| **Heuristic Engine** | 12-rule engine | Punycode, brand spoofing, suspicious TLDs, UPI fraud |
| **Rust WASM Extractor** | wasm-bindgen · 48 features | Shannon entropy, n-grams, gibberish detection |
| **ML Ensemble** | Random Forest + GBM · ONNX | Soft-vote probability, on-device inference |
| **DOM Analyzer** | MutationObserver | Fake login forms, clipboard hijacking, invisible iframes |
| **Download Scanner** | chrome.downloads API | Blocks `.exe`, `.scr`, `.ps1`, double-extension files |
| **Blockchain Ledger** | SHA-256 · Web Crypto API | Tamper-proof threat log stored locally |
| **UPI Fraud Detection** | VPA pattern matching | Flags fraudulent UPI collect requests |

---

## 🚀 Quick Setup (Load as Extension)

### Prerequisites
- **Microsoft Edge** or **Google Chrome** (any recent version)
- **Node.js** ≥ 18 + **npm**
- **Python** ≥ 3.10 (for ML model training — optional)
- **Rust** + **wasm-pack** (for WASM compilation — optional)

---

### Step 1 — Clone the Repo

```bash
git clone https://github.com/Prekshas27/Browser-Vigilant.git
cd Browser-Vigilant
```

---

### Step 2 — Build the Popup UI

```bash
cd popup
npm install
npm run build
cd ..
```

This creates `dist-popup/` with the compiled Svelte popup.

> ⚠️ Do **not** use `npm run dev` for loading into the extension — only `npm run build` works.

---

### Step 3 — Load the Extension in Edge / Chrome

1. Open **`edge://extensions`** (Edge) or **`chrome://extensions`** (Chrome)
2. Enable **Developer Mode** (toggle in the bottom-left / top-right)
3. Click **"Load unpacked"**
4. Select the **root folder**: `d:\Browser-Vigilant` (the folder containing `manifest.json`)
5. The **Browser Vigilant** extension will appear with a shield icon 🛡

**To open the popup:** Click the shield icon in the browser toolbar. If not visible, click the 🧩 Extensions puzzle icon and **pin** Browser Vigilant.

---

### Step 4 — Reload After Code Changes

Any time you modify `background.js`, `content.js`, or `manifest.json`:
1. Go to `edge://extensions`
2. Find Browser Vigilant → click **Reload**

Any time you modify the Svelte popup (`popup/src/**`):
```bash
cd popup && npm run build
```
Then reload the extension.

---

## 🤖 ML Model Setup (Optional — Heuristics work without it)

The ML layer uses a Random Forest + Gradient Boosting ensemble exported to ONNX.

### Step 1 — Create a Python Virtual Environment

```bash
cd model
python -m venv venv
```

### Step 2 — Activate the Virtual Environment

```bash
# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Train the Model

```bash
python train.py
```

This creates `model/model.onnx`. Copy it to the extension root or update the path in `content.js`.

### Step 5 — Deactivate When Done

```bash
deactivate
```

---

## 🦀 WASM Feature Extractor (Optional — Heuristics work without it)

The Rust WASM module extracts 48 URL features for ML inference.

```bash
# Install Rust (if not already)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install wasm-pack
cargo install wasm-pack

# Build the WASM module
cd wasm-feature
wasm-pack build --target web --out-dir ../wasm-build
```

---

## 📁 Project Structure

```
Browser-Vigilant/
├── manifest.json          # Extension manifest (MV3)
├── background.js          # Service worker: pre-nav scanner, blockchain, downloads
├── content.js             # Page-level: WASM + ONNX + heuristics + DOM analysis
├── block.html             # Threat blocked page
├── style.css              # Injected warning banner styles
├── ort.min.js             # ONNX Runtime (bundled)
├── ort-wasm.wasm          # ORT WASM backend
├── ort-wasm-simd.wasm     # ORT WASM SIMD backend
│
├── popup/                 # Svelte 5 + Vite popup UI
│   ├── src/
│   │   ├── App.svelte     # Main shell + tab router
│   │   ├── app.css        # Design tokens (dark mode)
│   │   └── components/
│   │       ├── Shield.svelte     # Live scan results + URL scanner
│   │       ├── History.svelte    # Scan log (filterable, exportable)
│   │       ├── ThreatMap.svelte  # SHA-256 blockchain ledger viewer
│   │       └── Settings.svelte   # Protection settings
│   └── vite.config.js
│
├── dist-popup/            # Built popup (auto-generated by npm run build)
│
├── model/                 # ML pipeline
│   ├── features.py        # Python mirror of the 48 WASM features
│   ├── train.py           # Trains RF+GBM ensemble → model.onnx
│   ├── convert.py         # Converts .pkl → ONNX
│   └── requirements.txt   # Python dependencies
│
├── wasm-feature/          # Rust WASM feature extractor
│   ├── Cargo.toml
│   └── src/lib.rs         # 48-feature extractor (mirrors features.py)
│
└── wasm-build/            # Compiled WASM output (from wasm-pack)
    ├── wasm_feature.js
    ├── wasm_feature_bg.wasm
    └── wasm_feature.d.ts
```

---

## 🔒 How Protection Works

### Before Any Page Loads
```
User types URL → webNavigation.onBeforeNavigate fires (background.js)
                → 12-rule heuristic scan runs (< 2ms)
                   → SAFE: allow through
                   → WARNING: OS notification shown immediately
                   → THREAT: redirect to block.html (page never opens)
```

### After Page Loads (Deep Scan)
```
Page DOM ready → content.js runs
              → Layer 1: Rust WASM extracts 48 features
              → Layer 2: ONNX ML ensemble scores URL (RF + GBM)
              → Layer 3: Full heuristic engine (12+ rules)
              → Layer 4: DOM behavioral analysis (MutationObserver)
              → Verdict computed → badge + popup updated
```

---

## ⚙️ Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Real-Time Shield | ✅ On | Enable/disable all scanning |
| Auto-Block Threats | ✅ On | Redirect to block.html on threat |
| ML Block Threshold | 50% | Minimum ML probability to block |
| UPI Fraud Detection | ✅ On | Scan DOM for fraudulent VPA addresses |
| Download Scanner | ✅ On | Block malicious file downloads |
| DOM Analysis | ✅ On | Deep behavioral DOM inspection |
| Notifications | ✅ On | OS notifications for warnings/blocks |
| Strict Mode | ❌ Off | Lower threshold — flags borderline sites |

---

## 🛠 Development Workflow

```bash
# 1. Start Svelte dev server (for UI iteration only — NOT for extension testing)
cd popup && npm run dev

# 2. After UI changes, build for production
cd popup && npm run build

# 3. Reload extension in Edge/Chrome
# Go to edge://extensions → Browser Vigilant → Reload
```

---

## 🔐 Privacy

- **Zero data uploaded** — all analysis is 100% on-device
- **No external API calls** — works offline
- **Blockchain ledger** — SHA-256 chained, stored in `chrome.storage.local`
- **No telemetry** — no analytics, no tracking

---

## 📄 License

MIT © 2025 Prekshas27
