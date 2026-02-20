// wasm-feature/src/lib.rs
// Browser Vigilant — 48-feature URL extractor
// All features use real mathematical formulas.
// Feature order MUST match model/features.py exactly.

use wasm_bindgen::prelude::*;

// ── Constants ─────────────────────────────────────────────────────────────────

const BRANDS: &[&str] = &[
    "google","facebook","amazon","apple","microsoft","paypal","netflix",
    "instagram","twitter","linkedin","whatsapp","youtube","yahoo","ebay",
    "dropbox","spotify","adobe","chase","wellsfargo","bankofamerica",
    "citi","hsbc","barclays","halifax","natwest","santander","lloyds",
    "steam","roblox","epic","coinbase","binance","metamask","opensea",
    "paytm","phonepe","gpay","bhim","razorpay","hdfc","icici","sbi",
    "axis","kotak","airtel","jio","vodafone","bsnl","flipkart","myntra",
];

const SUSPICIOUS_TLDS: &[&str] = &[
    "xyz","tk","top","cf","ml","ga","gq","pw","cc","icu","club","online",
    "site","website","space","live","click","link","info","biz","work",
    "tech","store","shop",
];

const LEGIT_UPI_HANDLES: &[&str] = &[
    "okaxis","okicici","oksbi","okhdfcbank","ybl","ibl","axl","apl","fbl",
    "upi","paytm","waaxis","waxis","rajgovhdfcbank","barodampay","allbank",
    "andb","aubank","cnrb","csbpay","dbs","dcb","federal","hdfcbank","idbi",
    "idfc","indus","idfcbank","jio","kotak","lvb","mahb","nsdl","pnb",
    "psb","rbl","sib","tjsb","uco","union","united","vijb","yapl","airtel",
    "airtelpaymentsbank","postbank",
];

const SHORT_SERVICES: &[&str] = &[
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
    "adf.ly","tiny.cc","clck.ru","cutt.ly","rb.gy","short.io","v.gd",
];

const DANGEROUS_EXTS: &[&str] = &[
    "exe","scr","bat","cmd","ps1","vbs","wsf","hta","jar","msi","msp",
    "reg","dll","pif","com","cpl","inf","apk","ipa","dmg","pkg","deb","rpm",
];

const LOGIN_KW: &[&str] = &[
    "login","signin","sign-in","account","verify","auth","authenticate","confirm",
];
const TRUST_KW: &[&str] = &["secure","safe","trust","bank","protected","official"];
const PAY_KW:   &[&str] = &["pay","payment","wallet","upi","gpay","paytm","bhim","razorpay","phonepay"];
const FREE_KW:  &[&str] = &["free","bonus","prize","winner","giveaway","reward","claim","gift","lucky"];
const FRAUD_PFX:&[&str] = &["refund","tax","prize","block","kyc","urgent","helpdesk","support","care"];

// ── Math ──────────────────────────────────────────────────────────────────────

/// Shannon entropy H = -Σ p(c) * log2(p(c))
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    let bytes = s.as_bytes();
    for &b in bytes { freq[b as usize] += 1; }
    let n = bytes.len() as f32;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f32 / n; -p * p.log2() })
        .sum()
}

/// Wagner-Fischer Levenshtein distance O(min(m,n)) space
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (a, b) = if a.len() < b.len() { (&b, &a) } else { (&a, &b) };
    let m = a.len(); let n = b.len();
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i-1] == b[j-1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j-1] + 1).min(prev[j-1] + cost);
        }
        prev.clone_from(&curr);
    }
    prev[n]
}

fn min_brand_distance(domain: &str) -> usize {
    let core = domain.split('.').next().unwrap_or("").to_lowercase();
    BRANDS.iter().map(|b| levenshtein(&core, b)).min().unwrap_or(99)
}

fn max_consecutive_consonants(s: &str) -> usize {
    let vowels = "aeiou";
    let (mut max_run, mut cur) = (0usize, 0usize);
    for c in s.to_lowercase().chars() {
        if c.is_alphabetic() && !vowels.contains(c) {
            cur += 1;
            if cur > max_run { max_run = cur; }
        } else {
            cur = 0;
        }
    }
    max_run
}

fn count_hex_encoded(url: &str) -> usize {
    let bytes = url.as_bytes();
    let mut count = 0usize;
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%' && bytes[i+1].is_ascii_hexdigit() && bytes[i+2].is_ascii_hexdigit() {
            count += 1;
            i += 3;
        } else {
            i += 1;
        }
    }
    count
}

/// Detect IP address (dotted quad) in host string
fn has_ip(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

// ── URL parser ────────────────────────────────────────────────────────────────

struct UrlParts {
    scheme:  String,
    host:    String,
    path:    String,
    query:   String,
    fragment:String,
    port:    Option<u16>,
    tld:     String,
    reg_domain: String,
    subdomain:  String,
    labels:  Vec<String>,
}

fn parse_url(url: &str) -> UrlParts {
    let low = url.to_lowercase();
    // scheme
    let (scheme, rest) = if let Some(pos) = low.find("://") {
        (&low[..pos], &url[pos+3..])
    } else {
        ("", url)
    };
    // fragment
    let (rest, fragment) = if let Some(pos) = rest.find('#') {
        (&rest[..pos], rest[pos+1..].to_string())
    } else { (rest, String::new()) };
    // query
    let (rest, query) = if let Some(pos) = rest.find('?') {
        (&rest[..pos], rest[pos+1..].to_string())
    } else { (rest, String::new()) };
    // host+path
    let (netloc, path) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], rest[pos..].to_string())
    } else { (rest, String::new()) };
    // strip auth (user:pass@host)
    let netloc = if let Some(pos) = netloc.rfind('@') { &netloc[pos+1..] } else { netloc };
    // strip port
    let (host, port) = if let Some(pos) = netloc.rfind(':') {
        let maybe_port = &netloc[pos+1..];
        if maybe_port.chars().all(|c| c.is_ascii_digit()) {
            (netloc[..pos].to_string(), maybe_port.parse::<u16>().ok())
        } else {
            (netloc.to_string(), None)
        }
    } else { (netloc.to_string(), None) };

    let labels: Vec<String> = host.split('.').map(|s| s.to_lowercase()).collect();
    let tld = labels.last().cloned().unwrap_or_default();
    let reg_domain = if labels.len() >= 2 {
        labels[labels.len()-2..].join(".")
    } else { host.clone() };
    let subdomain = if labels.len() > 2 {
        labels[..labels.len()-2].join(".")
    } else { String::new() };

    UrlParts {
        scheme: scheme.to_string(), host, path, query, fragment, port,
        tld, reg_domain, subdomain, labels,
    }
}

// ── Main exported function ────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn extract_features(url: &str) -> Vec<f32> {
    let mut f = vec![0.0f32; 48];
    let p   = parse_url(url);
    let low = url.to_lowercase();
    let host  = &p.host;
    let path  = &p.path;
    let query = &p.query;
    let tld   = &p.tld;
    let domain = &p.reg_domain;
    let sub    = &p.subdomain;

    // 0  URL total length
    f[0] = url.len() as f32;
    // 1  Host length
    f[1] = host.len() as f32;
    // 2  Path length
    f[2] = path.len() as f32;
    // 3  Query length
    f[3] = query.len() as f32;
    // 4  Dots in whole URL
    f[4] = url.matches('.').count() as f32;
    // 5  Hyphens
    f[5] = url.matches('-').count() as f32;
    // 6  Underscores
    f[6] = url.matches('_').count() as f32;
    // 7  Slashes after protocol
    let no_proto = if let Some(pos) = url.find("://") { &url[pos+3..] } else { url };
    f[7] = no_proto.matches('/').count() as f32;
    // 8  At-signs
    f[8] = url.matches('@').count() as f32;
    // 9  Digit count
    let digits = url.chars().filter(|c| c.is_ascii_digit()).count();
    f[9]  = digits as f32;
    // 10 Digit ratio
    f[10] = digits as f32 / url.len().max(1) as f32;
    // 11 HTTPS flag
    f[11] = if p.scheme == "https" { 1.0 } else { 0.0 };
    // 12 IP in host
    f[12] = if has_ip(host) { 1.0 } else { 0.0 };
    // 13 Punycode
    f[13] = if host.contains("xn--") { 1.0 } else { 0.0 };
    // 14 Subdomain depth
    f[14] = p.labels.len().saturating_sub(2) as f32;
    // 15 URL Shannon entropy
    f[15] = shannon_entropy(url);
    // 16 Host Shannon entropy
    f[16] = shannon_entropy(host);
    // 17 Path Shannon entropy
    f[17] = shannon_entropy(path);
    // 18 Suspicious TLD
    f[18] = if SUSPICIOUS_TLDS.contains(&tld.as_str()) { 1.0 } else { 0.0 };
    // 19 Brand spoof (min Levenshtein ≤ 2, not exact match)
    let min_dist = min_brand_distance(domain);
    f[19] = if min_dist > 0 && min_dist <= 2 { 1.0 } else { 0.0 };
    // 20 Normalized min brand distance
    f[20] = (min_dist.min(10) as f32) / 10.0;
    // 21 Login keywords
    f[21] = if LOGIN_KW.iter().any(|k| low.contains(k)) { 1.0 } else { 0.0 };
    // 22 Trust keywords in host
    f[22] = if TRUST_KW.iter().any(|k| host.contains(k)) { 1.0 } else { 0.0 };
    // 23 Payment keywords
    f[23] = if PAY_KW.iter().any(|k| low.contains(k)) { 1.0 } else { 0.0 };
    // 24 Free/prize keywords
    f[24] = if FREE_KW.iter().any(|k| low.contains(k)) { 1.0 } else { 0.0 };
    // 25 Hyphen in host
    f[25] = if host.contains('-') { 1.0 } else { 0.0 };
    // 26 Double extension (.pdf.exe etc.)
    let double_ext = ["pdf","doc","docx","xls","jpg","jpeg","png","gif","zip"];
    let danger_ext = ["exe","js","php","bat","ps1","vbs","cmd","scr","dll"];
    let path_low = path.to_lowercase();
    f[26] = if double_ext.iter().any(|de| danger_ext.iter().any(|xe|
        path_low.contains(&format!(".{}.{}", de, xe)))) { 1.0 } else { 0.0 };
    // 27 Percent-encoding ratio
    let pct = count_hex_encoded(url);
    f[27] = pct as f32 / url.len().max(1) as f32;
    // 28 Query param count
    f[28] = if query.is_empty() { 0.0 } else { query.matches('&').count() as f32 + 1.0 };
    // 29 Non-standard port
    f[29] = match p.port {
        None => 0.0,
        Some(pt) if pt == 80 || pt == 443 || pt == 8080 || pt == 8443 => 0.0,
        Some(_) => 1.0,
    };
    // 30 Path depth (slashes in path)
    f[30] = path.matches('/').count() as f32;
    // 31 Fragment present
    f[31] = if !p.fragment.is_empty() { 1.0 } else { 0.0 };
    // 32 Data URI
    f[32] = if low.starts_with("data:") { 1.0 } else { 0.0 };
    // 33 Path traversal
    f[33] = if path.contains("..") || low.contains("%2e%2e") { 1.0 } else { 0.0 };
    // 34 Base64-like string in query (≥20 base64 chars contiguous)
    f[34] = {
        let mut has_b64 = false;
        let qb = query.as_bytes();
        let mut run = 0usize;
        for &b in qb {
            if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
                run += 1;
                if run >= 20 { has_b64 = true; break; }
            } else { run = 0; }
        }
        if has_b64 { 1.0 } else { 0.0 }
    };
    // 35 Hex encoding density
    f[35] = (pct as f32 / (url.len() as f32 / 3.0).max(1.0)).min(1.0);
    // 36 TLD length
    f[36] = tld.len() as f32;
    // 37 Has subdomain
    f[37] = if !sub.is_empty() { 1.0 } else { 0.0 };
    // 38 Domain is numeric (decimal IP)
    f[38] = if host.chars().all(|c| c.is_ascii_digit() || c == '.') { 1.0 } else { 0.0 };
    // 39 UPI VPA in URL
    let upi_found = find_upi_vpa(url);
    f[39] = if !upi_found.is_empty() { 1.0 } else { 0.0 };
    // 40 Suspicious UPI handle
    f[40] = {
        let mut sus = 0.0f32;
        for (prefix, handle) in &upi_found {
            let h = handle.as_str();
            if !LEGIT_UPI_HANDLES.contains(&h) {
                sus = 1.0; break;
            }
            if FRAUD_PFX.iter().any(|fp| prefix.contains(fp)) {
                sus = 1.0; break;
            }
        }
        sus
    };
    // 41 Dangerous file extension in path
    f[41] = {
        let ext = path_low.rsplit('.').next().unwrap_or("").split('?').next().unwrap_or("").split('#').next().unwrap_or("");
        if DANGEROUS_EXTS.contains(&ext) { 1.0 } else { 0.0 }
    };
    // 42 Short URL service
    f[42] = if SHORT_SERVICES.contains(&domain.as_str()) { 1.0 } else { 0.0 };
    // 43 Brand in subdomain but not registered domain
    let brand_in_sub = BRANDS.iter().any(|b| sub.contains(b));
    let brand_in_reg = domain.split('.').next().map(|d| BRANDS.iter().any(|b| d.contains(b))).unwrap_or(false);
    f[43] = if brand_in_sub && !brand_in_reg { 1.0 } else { 0.0 };
    // 44 URL compression ratio (unique chars / len)
    let unique: std::collections::HashSet<char> = url.chars().collect();
    f[44] = unique.len() as f32 / url.len().max(1) as f32;
    // 45 Vowel ratio in host
    let vowels: usize = host.chars().filter(|c| "aeiou".contains(*c)).count();
    let alpha: usize  = host.chars().filter(|c| c.is_alphabetic()).count();
    f[45] = vowels as f32 / alpha.max(1) as f32;
    // 46 Max consecutive consonants in host (gibberish score)
    f[46] = max_consecutive_consonants(host) as f32;
    // 47 Total keyword density
    let all_kw_count = LOGIN_KW.iter().chain(TRUST_KW).chain(PAY_KW).chain(FREE_KW)
        .filter(|k| low.contains(*k)).count();
    f[47] = (all_kw_count as f32 / 5.0).min(1.0);

    f
}

// ── UPI VPA parser ────────────────────────────────────────────────────────────

/// Finds all UPI VPA patterns (prefix@handle) in a URL.
/// Returns Vec<(prefix, handle)>.
fn find_upi_vpa(text: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            // scan backwards for prefix
            let prefix_start = {
                let mut s = i;
                while s > 0 && (bytes[s-1].is_ascii_alphanumeric() ||
                    bytes[s-1] == b'.' || bytes[s-1] == b'_' || bytes[s-1] == b'-') {
                    s -= 1;
                }
                s
            };
            // scan forwards for handle
            let handle_end = {
                let mut e = i + 1;
                while e < bytes.len() && bytes[e].is_ascii_alphabetic() {
                    e += 1;
                }
                e
            };
            if prefix_start < i && handle_end > i + 1 {
                let prefix = text[prefix_start..i].to_lowercase();
                let handle = text[i+1..handle_end].to_lowercase();
                if !prefix.is_empty() && handle.len() >= 2 {
                    results.push((prefix, handle));
                }
            }
            i = handle_end;
        } else {
            i += 1;
        }
    }
    results
}

// ── DOM analysis exported functions ──────────────────────────────────────────

/// Analyze a serialized form-action URL against the current page host.
/// Returns risk score 0.0–1.0.
#[wasm_bindgen]
pub fn analyze_form_action(form_action: &str, page_host: &str) -> f32 {
    if form_action.is_empty() { return 0.0; }
    let action_low = form_action.to_lowercase();
    // Data URI form action — critical
    if action_low.starts_with("data:") { return 1.0; }
    // External domain form action
    let action_parts = parse_url(form_action);
    if !action_parts.host.is_empty() && !action_parts.host.contains(page_host)
        && !page_host.contains(&action_parts.host) {
        return 0.8;
    }
    0.0
}

/// Compute filename risk score for download interception.
/// Returns 0.0–1.0 risk.
#[wasm_bindgen]
pub fn score_filename(filename: &str) -> f32 {
    let low = filename.to_lowercase();
    let mut score = 0.0f32;
    // Dangerous primary extension
    let ext = low.rsplit('.').next().unwrap_or("");
    if DANGEROUS_EXTS.contains(&ext) { score += 0.6; }
    // Double extension
    let parts: Vec<&str> = low.split('.').collect();
    if parts.len() >= 3 {
        let penult = parts[parts.len() - 2];
        if DANGEROUS_EXTS.contains(&penult) { score += 0.4; }
    }
    // High filename entropy (gibberish / randomly named malware)
    let entropy = shannon_entropy(filename);
    if entropy > 4.5 { score += 0.2; }
    // Brand + exe pattern
    if BRANDS.iter().any(|b| low.contains(b)) && DANGEROUS_EXTS.contains(&ext) {
        score += 0.3;
    }
    score.min(1.0)
}
