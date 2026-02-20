async function blockPage() {
    // Replace DOM with the designated warning screen
    document.documentElement.innerHTML = `
        <head>
            <title>Scam Website Blocked</title>
            <link rel="stylesheet" href="${chrome.runtime.getURL('style.css')}">
        </head>
        <body>
            <div id="browser-vigilant-block-screen">
                <div class="icon">⚠</div>
                <h1>Scam Website Blocked</h1>
                <p>Browser Vigilant has prevented access to this page because it matches known phishing behavior.</p>
            </div>
        </body>
    `;
    document.documentElement.style.overflow = 'hidden';
}

async function runModel(featuresArray) {
    try {
        const modelUrl = chrome.runtime.getURL("model/model.onnx");

        // Define paths to ONNX WASM binaries required for inference in MV3
        ort.env.wasm.wasmPaths = chrome.runtime.getURL("");

        const session = await ort.InferenceSession.create(modelUrl, {
            executionProviders: ['wasm']
        });

        // Ensure 1x30 float32 tensor
        const tensor = new ort.Tensor('float32', Float32Array.from(featuresArray), [1, 30]);
        const results = await session.run({ "input": tensor });

        // Depending on sklearn-onnx version and model, it outputs output_label or label
        const predictionTensor = results.output_label || results.label;
        const prediction = predictionTensor.data[0];

        console.log("Browser Vigilant Prediction Result:", prediction);
        return prediction;
    } catch (e) {
        console.error("Browser Vigilant Model Error:", e);
        return 0; // Default to allow if inference fails
    }
}

async function executeVigilant() {
    console.log("Browser Vigilant analyzing:", window.location.href);

    // 1. Dymamic module import from web accessible resources to bypass MV3 script limitations
    const wasmModulePath = chrome.runtime.getURL("wasm-build/wasm_feature.js");
    const { default: initWasm, extract_features } = await import(wasmModulePath);

    // 2. Initialize the WebAssembly runtime
    const wasmBinaryPath = chrome.runtime.getURL("wasm-build/wasm_feature_bg.wasm");
    await initWasm(wasmBinaryPath);
    console.log("WASM module loaded successfully.");

    // 3. Extract features using the WASM Rust logic
    const url = window.location.href;
    const featuresArray = extract_features(url);
    console.log("Extracted Features Dimension:", featuresArray.length);

    // 4. Run the locally hosted ONNX Machine Learning Model
    const prediction = await runModel(featuresArray);

    // 5. Binary decision enforcement:
    // If prediction holds a value equivalent to 1 (can be BigInt depending on Tensor type)
    if (prediction == 1 || prediction == 1n) {
        console.warn("Blocked! Phishing attempt detected.");
        blockPage();
    } else {
        console.log("Allowed. Safe website.");
    }
}

// Ensure the code behaves robustly even on pages with strict CSP
try {
    executeVigilant();
} catch (error) {
    console.error("Browser Vigilant Initialization Error:", error);
}
