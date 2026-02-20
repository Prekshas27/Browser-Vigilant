// WASM Feature Loader - Simplified version that works
let wasmModule = null;
let wasmExports = null;
let isWasmReady = false;

// Simple fallback feature extractor (basic implementation)
function extractFeaturesFallback(url) {
    // Basic feature extraction without WASM
    const features = new Array(56).fill(0);

    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const path = urlObj.pathname;
        const query = urlObj.search;

        // Basic features (simplified)
        features[0] = url.length; // URL length
        features[1] = hostname.length; // Domain length
        features[2] = path.length; // Path length
        features[3] = query.length; // Query length
        features[4] = (url.match(/\./g) || []).length; // Dot count
        features[5] = (url.match(/-/g) || []).length; // Hyphen count
        features[6] = (url.match(/_/g) || []).length; // Underscore count
        features[7] = (url.match(/\//g) || []).length; // Slash count
        features[8] = (url.match(/@/g) || []).length; // At-sign count
        features[9] = (url.match(/\d/g) || []).length; // Digit count
        features[10] = url.startsWith('https') ? 1 : 0; // HTTPS flag
        features[11] = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname) ? 1 : 0; // IP in URL
        features[12] = hostname.includes('xn--') ? 1 : 0; // Punycode
        features[13] = hostname.split('.').length - 1; // Subdomain depth
        features[14] = [80, 443, 8080].includes(urlObj.port || (url.startsWith('https') ? 443 : 80)) ? 0 : 1; // Port anomaly

        // Simple entropy calculation
        const charFreq = {};
        for (let char of url) {
            charFreq[char] = (charFreq[char] || 0) + 1;
        }
        let entropy = 0;
        const urlLen = url.length;
        for (let freq of Object.values(charFreq)) {
            const probability = freq / urlLen;
            entropy -= probability * Math.log2(probability);
        }
        features[15] = entropy; // URL entropy
        features[16] = entropy; // Domain entropy (simplified)
        features[17] = entropy; // Path entropy (simplified)

    } catch (error) {
        console.warn('[WASM] Feature extraction fallback error:', error);
    }

    return features;
}

// Expose functions globally
window.wasmFeatureExtractor = {
    extract_features: extractFeaturesFallback,
    analyze_form_action: (form_action, page_host) => {
        if (form_action.startsWith('data:')) return 1.0;
        if (form_action.includes(page_host)) return 0.0;
        return 0.8;
    },
    score_filename: (filename) => {
        const low = filename.toLowerCase();
        const ext = low.split('.').pop() || '';
        const dangerous = ['exe', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'wsf', 'hta', 'jar', 'msi'];
        return dangerous.includes(ext) ? 0.8 : 0.1;
    }
};

console.log('[WASM] Fallback feature extractor ready');
isWasmReady = true;

// Export for use in content scripts
window.loadWasmFeatureExtractor = async () => {
    try {
        const wasmGlueUrl = chrome.runtime.getURL('wasm-build/wasm_feature.js');
        const wasmModule = await import(wasmGlueUrl);
        const wasmUrl = chrome.runtime.getURL('wasm-build/wasm_feature_bg.wasm');
        await wasmModule.default({ module_or_path: wasmUrl });

        window.wasmFeatureExtractor = {
            extract_features: (url) => {
                try {
                    return Array.from(wasmModule.extract_features(url));
                } catch (e) {
                    console.warn('[WASM] Fallback for URL:', url, e);
                    return extractFeaturesFallback(url);
                }
            },
            analyze_form_action: wasmModule.analyze_form_action,
            score_filename: wasmModule.score_filename
        };
        console.log('[WASM] Real WASM feature extractor loaded successfully');
        isWasmReady = true;
        return window.wasmFeatureExtractor;
    } catch (e) {
        console.warn('[WASM] Failed to load real WASM, using fallback', e);
        // Fallback is already set globally
        return window.wasmFeatureExtractor;
    }
};

window.getWasmFunctions = () => window.wasmFeatureExtractor;

// Start loading immediately
window.loadWasmFeatureExtractor();