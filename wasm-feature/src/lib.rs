use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn extract_features(url: &str) -> Vec<f32> {
    // 30 features list:
    let mut features = vec![0.0; 30];
    
    // Feature 0: URL length
    features[0] = url.len() as f32;
    
    // Feature 1: Number of dots
    features[1] = url.matches('.').count() as f32;
    
    // Feature 2: Presence of IPv4 address in the URL (basic heuristic)
    features[2] = if regex_like_ip(url) { 1.0 } else { 0.0 }; // Mock logic
    
    // Feature 3: HTTPS usage
    features[3] = if url.starts_with("https://") { 1.0 } else { 0.0 };
    
    // Feature 4: Presence of '@'
    features[4] = if url.contains('@') { 1.0 } else { 0.0 };
    
    // Feature 5: Hyphen in domain (very basic split logic)
    let domain = url.split('/').nth(2).unwrap_or("");
    features[5] = if domain.contains('-') { 1.0 } else { 0.0 };
    
    // Feature 6: Number of subdomains (dots in domain)
    let domain_dots = domain.matches('.').count() as f32;
    let subdomains = if domain_dots > 1.0 { domain_dots - 1.0 } else { 0.0 };
    features[6] = subdomains;

    // Feature 7-10: Suspicious keywords
    let lower_url = url.to_lowercase();
    features[7] = if lower_url.contains("login") { 1.0 } else { 0.0 };
    features[8] = if lower_url.contains("secure") { 1.0 } else { 0.0 };
    features[9] = if lower_url.contains("verify") { 1.0 } else { 0.0 };
    features[10] = if lower_url.contains("update") { 1.0 } else { 0.0 };
    
    // Feature 11: Digit ratio in URL
    let digit_count = url.chars().filter(|c| c.is_digit(10)).count() as f32;
    features[11] = if url.len() > 0 { digit_count / url.len() as f32 } else { 0.0 };
    
    // Feature 12-29: Mock features to match the exact 30 limit required by the RF model
    // In a real application, these would be the remaining extracted features.
    for i in 12..30 {
        features[i] = (url.len() % i) as f32 * 0.1; 
    }

    features
}

fn regex_like_ip(url: &str) -> bool {
    let parts: Vec<&str> = url.split('.').collect();
    if parts.len() == 4 {
        parts.iter().all(|&p| p.parse::<u8>().is_ok())
    } else {
        false
    }
}
