"""
features.py — Python mirror of wasm-feature/src/lib.rs
Produces identically ordered 48 float features from a URL string.
This MUST stay in sync with lib.rs whenever features change.
"""

import math
import re
from urllib.parse import urlparse

# ── Constants ──────────────────────────────────────────────────────────────────

BRANDS = [
    "google","facebook","amazon","apple","microsoft","paypal","netflix",
    "instagram","twitter","linkedin","whatsapp","youtube","yahoo","ebay",
    "dropbox","spotify","adobe","chase","wellsfargo","bankofamerica",
    "citi","hsbc","barclays","halifax","natwest","santander","lloyds",
    "steam","roblox","epic","coinbase","binance","metamask","opensea",
    "paytm","phonepe","gpay","bhim","razorpay","hdfc","icici","sbi",
    "axis","kotak","airtel","jio","vodafone","bsnl","flipkart","myntra",
]

SUSPICIOUS_TLDS = {
    "xyz","tk","top","cf","ml","ga","gq","pw","cc","icu","club","online",
    "site","website","space","live","click","link","info","biz","work",
    "tech","store","shop",
}

LEGIT_UPI_HANDLES = {
    "okaxis","okicici","oksbi","okhdfcbank","ybl","ibl","axl","apl","fbl",
    "upi","paytm","waaxis","waxis","rajgovhdfcbank","barodampay","allbank",
    "andb","aubank","cnrb","csbpay","dbs","dcb","federal","hdfcbank","idbi",
    "idfc","indus","idfcbank","jio","kotak","lvb","mahb","nsdl","pnb",
    "psb","rbl","sib","tjsb","uco","union","united","vijb","yapl","airtel",
    "airtelpaymentsbank","postbank",
}

SHORT_URL_SERVICES = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
    "adf.ly","tiny.cc","clck.ru","cutt.ly","rb.gy","short.io","v.gd",
}

DANGEROUS_EXTENSIONS = {
    "exe","scr","bat","cmd","ps1","vbs","wsf","hta","jar","msi","msp",
    "reg","dll","pif","com","cpl","inf","apk","ipa","dmg","pkg","deb","rpm",
}

# ── Math helpers ───────────────────────────────────────────────────────────────

def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f/n)*math.log2(f/n) for f in freq.values())

def levenshtein(a, b):
    m, n = len(a), len(b)
    if m < n:
        a, b, m, n = b, a, n, m
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        curr = [i] + [0]*n
        for j in range(1, n + 1):
            cost = 0 if a[i-1] == b[j-1] else 1
            curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
        prev = curr
    return prev[n]

def min_brand_distance(domain):
    core = domain.split(".")[0].lower()
    return min(levenshtein(core, b) for b in BRANDS)

def max_consecutive_consonants(s):
    vowels = set("aeiou")
    max_run = cur = 0
    for c in s.lower():
        if c.isalpha() and c not in vowels:
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 0
    return max_run

def parse_url_parts(url):
    try:
        p = urlparse(url)
        netloc    = p.netloc.lower()
        host_port = netloc.split("@")[-1]
        host, _, port_str = host_port.partition(":")
        port = int(port_str) if port_str.isdigit() else None
        labels = host.split(".")
        tld    = labels[-1] if labels else ""
        reg    = ".".join(labels[-2:]) if len(labels) >= 2 else host
        sub    = ".".join(labels[:-2]) if len(labels) > 2 else ""
        return dict(scheme=p.scheme.lower(), host=host, path=p.path,
                    query=p.query, fragment=p.fragment, port=port,
                    tld=tld, registered_domain=reg, subdomain=sub, labels=labels)
    except Exception:
        return dict(scheme="", host=url, path="", query="", fragment="",
                    port=None, tld="", registered_domain=url, subdomain="", labels=[url])

# ── Main extractor ─────────────────────────────────────────────────────────────

def extract_features(url):
    """Returns list[float] of exactly 48 features. Order matches lib.rs."""
    p = parse_url_parts(url)
    host   = p["host"]
    path   = p["path"]
    query  = p["query"]
    tld    = p["tld"]
    domain = p["registered_domain"]
    sub    = p["subdomain"]
    low    = url.lower()
    f = [0.0] * 48

    f[0]  = float(len(url))
    f[1]  = float(len(host))
    f[2]  = float(len(path))
    f[3]  = float(len(query))
    f[4]  = float(url.count("."))
    f[5]  = float(url.count("-"))
    f[6]  = float(url.count("_"))
    no_proto = url.split("//",1)[-1] if "//" in url else url
    f[7]  = float(no_proto.count("/"))
    f[8]  = float(url.count("@"))
    digits = sum(1 for c in url if c.isdigit())
    f[9]  = float(digits)
    f[10] = digits / max(len(url), 1)
    f[11] = 1.0 if p["scheme"] == "https" else 0.0
    f[12] = 1.0 if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", host) else 0.0
    f[13] = 1.0 if "xn--" in host else 0.0
    f[14] = float(max(len(p["labels"]) - 2, 0))
    f[15] = shannon_entropy(url)
    f[16] = shannon_entropy(host)
    f[17] = shannon_entropy(path)
    f[18] = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
    min_dist = min_brand_distance(domain)
    f[19] = 1.0 if 0 < min_dist <= 2 else 0.0
    f[20] = min(min_dist, 10) / 10.0
    login_kw  = {"login","signin","sign-in","account","verify","auth","authenticate","confirm"}
    trust_kw  = {"secure","safe","trust","bank","protected","official"}
    pay_kw    = {"pay","payment","wallet","upi","gpay","paytm","bhim","razorpay","phonepay"}
    free_kw   = {"free","bonus","prize","winner","giveaway","reward","claim","gift","lucky"}
    f[21] = 1.0 if any(k in low for k in login_kw) else 0.0
    f[22] = 1.0 if any(k in host for k in trust_kw) else 0.0
    f[23] = 1.0 if any(k in low for k in pay_kw) else 0.0
    f[24] = 1.0 if any(k in low for k in free_kw) else 0.0
    f[25] = 1.0 if "-" in host else 0.0
    dbl = re.compile(r"\.(pdf|doc|jpg|jpeg|png|gif|mp4|zip)\.(exe|js|php|bat|ps1|vbs|cmd|scr)", re.I)
    f[26] = 1.0 if dbl.search(path) else 0.0
    pct = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    f[27] = pct / max(len(url), 1)
    f[28] = float(len(query.split("&")) if query else 0)
    non_std = p["port"] not in (None, 80, 443, 8080, 8443)
    f[29] = 1.0 if (p["port"] is not None and non_std) else 0.0
    f[30] = float(path.count("/"))
    f[31] = 1.0 if p["fragment"] else 0.0
    f[32] = 1.0 if low.startswith("data:") else 0.0
    f[33] = 1.0 if (".." in path or "%2e%2e" in low) else 0.0
    f[34] = 1.0 if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", query) else 0.0
    f[35] = min(pct / max(len(url)/3, 1), 1.0)
    f[36] = float(len(tld))
    f[37] = 1.0 if sub else 0.0
    f[38] = 1.0 if re.fullmatch(r"[\d.]+", host) else 0.0
    upi_re = re.compile(r"[a-zA-Z0-9._-]+@[a-zA-Z]+")
    f[39] = 1.0 if upi_re.search(url) else 0.0
    suspicious_upi = 0.0
    fraud_pfx = {"refund","tax","prize","block","kyc","urgent","helpdesk","support","care"}
    for m in upi_re.finditer(url):
        handle = m.group().split("@")[-1].lower()
        prefix = m.group().split("@")[0].lower()
        if handle not in LEGIT_UPI_HANDLES or any(fp in prefix for fp in fraud_pfx):
            suspicious_upi = 1.0
            break
    f[40] = suspicious_upi
    ext_m = re.search(r"\.([a-zA-Z0-9]{1,5})(?:[?#]|$)", path)
    ext = ext_m.group(1).lower() if ext_m else ""
    f[41] = 1.0 if ext in DANGEROUS_EXTENSIONS else 0.0
    f[42] = 1.0 if domain in SHORT_URL_SERVICES else 0.0
    brand_sub = any(b in sub for b in BRANDS)
    brand_reg = any(b in domain.split(".")[0] for b in BRANDS)
    f[43] = 1.0 if (brand_sub and not brand_reg) else 0.0
    f[44] = len(set(url)) / max(len(url), 1)
    vowels = sum(1 for c in host if c in "aeiou")
    alpha  = sum(1 for c in host if c.isalpha())
    f[45] = vowels / max(alpha, 1)
    f[46] = float(max_consecutive_consonants(host))
    all_kw = login_kw | trust_kw | pay_kw | free_kw
    hits = sum(1 for k in all_kw if k in low)
    f[47] = min(hits / 5.0, 1.0)

    return f
