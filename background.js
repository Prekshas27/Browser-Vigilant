// content_scripts cannot always use web_accessible_resources directly if they are loaded differently,
// but for onnxruntime model loading it often needs the URL. 
// background.js is basically empty in this architecture as the work is done in content.js directly.
// keeping it here for completeness or future expansion.
chrome.runtime.onInstalled.addListener(() => {
    console.log("Browser Vigilant installed.");
});
