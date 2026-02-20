# Browser Vigilant 🛡️

A complete Chrome Extension that detects and blocks phishing/scam websites in real time using a locally running Machine Learning model. 

## Features
* **100% Client-Side:** Inference executed directly in the browser via `onnxruntime-web`.
* **Privacy Preserving:** Does NOT send browsing data anywhere.
* **Rust WebAssembly:** High-performance model feature extraction via `wasm-pack`.
* **Zero Backend API:** Uses ONNX compiled Random Forest model.

## 1. Environment Build Instructions

### Prerequisites
* Python 3.9+ 
* Rust and Cargo
* `wasm-pack`

### Step 1: Build the Machine Learning Model
The extension requires `model.onnx` initialized in the `model/` folder.
```bash
cd model
pip install -r requirements.txt

# Create the initial random_forest.pkl containing the model
python train_dummy.py

# Convert random_forest.pkl into model.onnx
python convert.py
cd ..
```

### Step 2: Compile Rust WebAssembly
Compile the `.rs` feature extraction script into our `wasm-build` integration.
```bash
cd wasm-feature
wasm-pack build --target web --out-dir ../wasm-build
cd ..
```

### Step 3: Install in Chrome
1. Open Google Chrome and navigate to `chrome://extensions/`
2. Toggle on **Developer mode** in the top right.
3. Click **Load unpacked** in the top left.
4. Select the `Browser-Vigilant` folder.

## 2. Testing the Extension
Once loaded, visit any URL. 
- Open Chrome DevTools (`F12`) -> **Console** to see the logs from Browser Vigilant processing the URL.
- The default setup relies on dummy mock data; adjust `train_dummy.py` thresholds or use the original `random_forest.pkl` from Sahi_Hai.
