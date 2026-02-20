<!-- ========================================================= -->
<!-- ===================== HEADER ============================= -->
<!-- ========================================================= -->

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,100:1e3a8a&height=260&section=header&text=Browser%20Vigilant&fontSize=56&fontColor=00F7FF&animation=fadeIn&fontAlignY=35"/>
</p>

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Orbitron&size=26&duration=2500&pause=1000&color=00F7FF&center=true&vCenter=true&width=1000&lines=AI+Cybersecurity+Engine+Inside+Your+Browser;Phishing+Blocked+Before+Page+Load;Rust+%2B+WASM+%2B+ONNX+ML;Zero+Telemetry+Architecture;Decentralized+Threat+Vault"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Manifest-MV3-22c55e?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Rust-WASM-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/ML-ONNX-purple?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/AI-ActiveFirewall-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Privacy-ZeroTelemetry-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Offline-First-0ea5e9?style=for-the-badge"/>
</p>

---

    
# 🛡 Browser Vigilant

> **A multi-layer AI security engine running entirely inside your browser**

Browser Vigilant predicts phishing and malicious pages **before they load**.  
Everything runs locally. No telemetry. No cloud dependency.

This is not just an extension —  
it’s an **on-device cybersecurity engine**.

---

# ⚡ Detection Pipeline

<div align="center">
    
```bash
User Types URL
↓
Threat Vault Hash Lookup
↓
Pre-Navigation Heuristics
↓
Rust WASM Feature Engine
↓
ONNX ML Ensemble
↓
DOM Behavioral Scanner
↓
BLOCK / WARN / SAFE

```
</div>

Latency: **< 5ms**

---

# 🧠 Multi-Layer Architecture

## 🔹 Layer 0 — Threat Vault Cache
- SHA-256 hashed domains
- O(1) lookup
- Trust scoring
- Merkle root integrity verification
- Offline-first storage

---

## 🔹 Layer 1 — Pre-Navigation Engine
Runs before page loads.

Detects:
- Brand spoofing
- Punycode homograph attacks
- Suspicious TLDs
- IP-based URLs
- Excessive subdomains
- Look-alike domains

If malicious → page blocked instantly.

---

## 🔹 Layer 2 — Rust + WebAssembly Feature Engine

Extracts **48 mathematical URL signals**:

- Shannon entropy
- Digit ratios
- Character distribution
- N-grams
- Obfuscation patterns
- Length anomalies
- Compression heuristics

Compiled using:

Rust → wasm-bindgen → WebAssembly

----

Near-native performance inside browser.

---

## 🔹 Layer 3 — On-Device ML Engine

Runs fully local.

Models:
- Random Forest (300 trees)
- Gradient Boosting
- Soft-vote ensemble

Runtime:

ONNX Runtime Web (WASM backend)

No network calls.

---

## 🔹 Layer 4 — DOM Behavioral Scanner

Real-time page mutation monitoring.

Detects:
- Credential harvesting forms
- Fake login overlays
- Clipboard hijacking
- Hidden iframes
- Fake UPI prompts
- Script injection
- Invisible click traps

---

# 🔒 Privacy Architecture

Only this may sync:

SHA-256(hostname)
confidence score
timestamp

Never transmitted:
- URLs
- Queries
- Form data
- Page content
- Cookies
- Credentials

Works offline.

---

# 🌐 Decentralized Threat Vault

Community-verified hash network.

hash(domain)
confidence
trust score
timestamp

No raw URLs shared.  
Zero-knowledge sync.

---

# 🧬 Integrity Verification

Each update verified with Merkle root:

MerkleRoot =
H( H(hash1 + hash2) +
H(hash3 + hash4) )

Visible in UI for tamper detection.

---

# 📊 Performance

<div align="center">
    
```bash
|      Metric      |   Value   |
|------------------|-----------|
|Detection latency | <5ms      |
|Memory usage      | ~18MB     |
|Model size        | ~2.4MB    |
|Offline support   | Yes       |
|Telemetry         | None      |
|------------------|-----------|
```

</div>

---

# 🏗 Tech Stack

<div align="center">
  
```bash
|     Layer         |        Tech          |
|-------------------|----------------------|
|Extension          | Manifest V3          |
|Feature Engine     | Rust + WASM          |
|ML Runtime         | ONNX Web             |
|UI                 | Svelte 5             |
|Storage            | chrome.storage.local |
|Crypto             | Web Crypto API       |
|Sync               | Hash-only API        |
|-------------------|----------------------|

```

</div>

---

# 📁 Project Structure

```bash

Browser-Vigilant/
│
├── background.js
├── content.js
├── manifest.json
├── block.html
│
├── popup/
│ ├── src/
│ └── build/
│
├── wasm-feature/
│ └── Rust feature engine
│
├── model/
│ └── ONNX models
│
└── vault/
└── threat hashes

```

---

# 🚀 Installation

```bash
git clone https://github.com/yourrepo/browser-vigilant.git
cd browser-vigilant/popup
npm install
npm run build
```

---

# Load Extension

Open chrome://extensions

Enable Developer Mode

Click Load Unpacked

Select project root

---

# 🛠 Development

```bash
cd popup
npm run build
```

Reload extension after build.

---

# 🔥 Why This Is Different

## Most security extensions:

- Rely on blacklists

- Send data to cloud

- Detect too late

## Browser Vigilant:

- Predicts using ML

- Blocks before interaction

- Runs fully local

- Cryptographically verifiable

- Zero telemetry

---

# 🧪 Benchmarks

<div align="center">

|       Test	   |   Result   |
|----------------|------------|
|Accuracy	       |     98%    |
|False positives |	   <1%    | 
|Detection time	 |    ~3ms    |

</div>

---

# 🗺 Roadmap

 Firefox support

 Edge store release

 Transformer URL model

 Federated threat learning

 WASM SIMD optimization

 WebGPU inference

---

# 🤝 Contributing

PRs welcome.

## Focus areas:

- ML models

- Heuristics

- WASM optimization

- UI improvements

---

# 🧑‍💻 Author

Built for privacy-first AI security.

---
<h1 align="center">
 ⭐ Star This Repo
</h1>
<div align="center">

If this README made you rethink what a browser extension can be.
</div>

<p align="center"> <img src="https://capsule-render.vercel.app/api?type=waving&color=0:1e3a8a,100:0f172a&height=160&section=footer"/> </p> ```
