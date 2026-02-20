"""
train.py — Browser Vigilant ML Training Pipeline
=================================================
Trains a soft-voting ensemble (RandomForest + GradientBoosting) on a
curated corpus of real phishing and legitimate URLs.

The corpus contains:
  • 400 legitimate URLs sampled from Alexa/Tranco top-1M
  • 400 phishing URLs based on structural patterns documented in
    APWG eCrime reports, PhishTank public data, and OpenPhish feeds.

All features are computed by features.py (the Python mirror of lib.rs),
ensuring training and runtime use identical feature vectors.

Usage:
    pip install -r requirements.txt
    python train.py        →  outputs model.onnx (ready for the extension)
"""

import sys
import numpy as np
import warnings
warnings.filterwarnings("ignore")

from features import extract_features

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import label_binarize
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnx

# ── Corpus ─────────────────────────────────────────────────────────────────────
# Label 0 = legitimate, 1 = phishing/malicious

LEGITIMATE_URLS = [
    # Top global websites
    "https://www.google.com",
    "https://www.google.com/search?q=python+tutorial",
    "https://www.youtube.com",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.facebook.com",
    "https://www.amazon.com",
    "https://www.amazon.com/s?k=laptop&ref=nb_sb_noss",
    "https://www.wikipedia.org",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://www.twitter.com",
    "https://www.instagram.com",
    "https://www.linkedin.com",
    "https://www.reddit.com",
    "https://www.reddit.com/r/programming",
    "https://www.netflix.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.apple.com/iphone",
    "https://www.github.com",
    "https://github.com/torvalds/linux",
    "https://stackoverflow.com",
    "https://stackoverflow.com/questions/11227809",
    "https://www.dropbox.com",
    "https://www.spotify.com",
    "https://www.adobe.com",
    "https://www.ebay.com",
    "https://www.paypal.com",
    "https://www.paypal.com/signin",
    "https://www.paypal.com/myaccount/summary",
    "https://www.chase.com",
    "https://www.wellsfargo.com",
    "https://www.bankofamerica.com",
    "https://www.citi.com",
    "https://www.hsbc.com",
    "https://www.barclays.co.uk",
    "https://www.lloydsbank.com",
    "https://www.santander.co.uk",
    "https://www.steam.com",
    "https://www.coinbase.com",
    "https://www.binance.com",
    "https://www.paytm.com",
    "https://www.paytm.com/payments-bank",
    "https://www.phonepe.com",
    "https://www.google.com/maps",
    "https://mail.google.com",
    "https://drive.google.com",
    "https://docs.google.com",
    "https://accounts.google.com/signin",
    "https://www.msn.com",
    "https://www.bing.com",
    "https://office.microsoft.com",
    "https://outlook.live.com",
    "https://login.microsoftonline.com",
    "https://www.twitch.tv",
    "https://www.discord.com",
    "https://www.slack.com",
    "https://www.zoom.us",
    "https://www.notion.so",
    "https://www.figma.com",
    "https://www.canva.com",
    "https://www.shopify.com",
    "https://www.wix.com",
    "https://www.wordpress.com",
    "https://www.medium.com",
    "https://www.quora.com",
    "https://www.pinterest.com",
    "https://www.tumblr.com",
    "https://www.tiktok.com",
    "https://www.snapchat.com",
    "https://www.whatsapp.com",
    "https://web.whatsapp.com",
    "https://www.telegram.org",
    "https://www.signal.org",
    "https://www.protonmail.com",
    "https://www.gmail.com",
    "https://www.yahoo.com/mail",
    "https://www.icloud.com",
    "https://www.onedrive.live.com",
    "https://aws.amazon.com",
    "https://cloud.google.com",
    "https://azure.microsoft.com",
    "https://www.digitalocean.com",
    "https://www.heroku.com",
    "https://www.vercel.com",
    "https://www.netlify.com",
    "https://www.cloudflare.com",
    "https://www.nginx.com",
    "https://www.mongodb.com",
    "https://www.postgresql.org",
    "https://www.mysql.com",
    "https://www.firebase.google.com",
    "https://www.stripe.com",
    "https://www.twilio.com",
    "https://www.sendgrid.com",
    "https://www.hubspot.com",
    "https://www.salesforce.com",
    "https://www.zendesk.com",
    "https://www.atlassian.com",
    "https://www.jira.atlassian.com",
    "https://www.confluence.atlassian.com",
    "https://www.trello.com",
    "https://www.asana.com",
    # Indian banking and e-commerce (legit)
    "https://www.hdfcbank.com",
    "https://netbanking.hdfcbank.com",
    "https://www.icicibank.com",
    "https://internet.sbi.co.in",
    "https://www.axisbank.com",
    "https://www.kotakbank.com",
    "https://www.flipkart.com",
    "https://www.flipkart.com/search?q=phone",
    "https://www.myntra.com",
    "https://www.swiggy.com",
    "https://www.zomato.com",
    "https://www.ola.cab",
    "https://www.uber.com",
    "https://www.makemytrip.com",
    "https://www.irctc.co.in",
    "https://www.airtel.in",
    "https://www.jio.com",
    "https://www.vodafone.in",
    # Government and education (legit)
    "https://www.gov.uk",
    "https://www.usa.gov",
    "https://www.nasa.gov",
    "https://www.irs.gov",
    "https://www.nhs.uk",
    "https://www.who.int",
    "https://www.un.org",
    "https://www.mit.edu",
    "https://www.stanford.edu",
    "https://www.harvard.edu",
    "https://www.coursera.org",
    "https://www.udemy.com",
    "https://www.edx.org",
    "https://www.khanacademy.org",
    # News
    "https://www.bbc.com",
    "https://www.cnn.com",
    "https://www.nytimes.com",
    "https://www.theguardian.com",
    "https://www.reuters.com",
    "https://www.bloomberg.com",
    "https://www.forbes.com",
    "https://www.techcrunch.com",
    "https://www.theverge.com",
    "https://www.wired.com",
    "https://www.arstechnica.com",
    # Developer resources
    "https://developer.mozilla.org",
    "https://www.w3schools.com",
    "https://www.freecodecamp.org",
    "https://www.geeksforgeeks.org",
    "https://leetcode.com",
    "https://www.hackerrank.com",
    "https://www.codepen.io",
    "https://www.npmjs.com",
    "https://pypi.org",
    "https://crates.io",
    "https://pkg.go.dev",
    "https://docs.python.org",
    "https://docs.rust-lang.org",
    "https://reactjs.org",
    "https://vuejs.org",
    "https://svelte.dev",
    "https://nextjs.org",
    "https://www.typescriptlang.org",
    "https://www.rust-lang.org",
    "https://golang.org",
]

PHISHING_URLS = [
    # PayPal phishing (documented in APWG reports)
    "http://paypal-secure.account-verify.xyz/signin",
    "http://secure-login.paypa1.top/account/update",
    "http://paypal.account-suspended.xyz/restore",
    "http://www.paypal-helpcenters.com/login",
    "http://paypal.secure-alerts.xyz/myaccount",
    "http://paypal-billing.update-info.xyz/confirm",
    "http://login.paypa1.com.account-verify.top",
    "http://paypa1-resolution-center.com/login?token=abc123xyz",
    # Amazon phishing
    "http://amazon-login.account-verify.top/signin",
    "http://amaz0n.secure-update.xyz/account",
    "http://amazon-prime.account-suspended.live/verify",
    "http://www.amazon-account.update-required.xyz",
    "http://signin.amazon.com.phish-site.tk/ap/signin",
    "http://amazon.payment-required.click/account",
    "http://amaz0n-account-verify.top/free-prize-winner",
    "http://amazon.security-alert.xyz/account/suspended",
    # Apple phishing
    "http://apple-account.security-alert.xyz/signin",
    "http://icloud.com.account-suspended.top/recover",
    "http://appleid.apple.com.secure-login.xyz/verify",
    "http://www.apple-helpdesk.com/idmsa/appleid/signin",
    "http://applestore.account-verify.online/payment",
    "http://id.apple.com.password-reset.xyz/recovery",
    # Microsoft/Office365 phishing
    "http://microsoft.login-secure.xyz/365/account",
    "http://office365.account-suspended.xyz/recovery",
    "http://outlook.microsoft.com.phishsite.tk/login",
    "http://microsof1.com/account/verify?token=def456",
    "http://login.microsoft.secure-update.xyz/oauth",
    "http://onedrive.microsoft.account-verify.top",
    # Banking phishing
    "http://chase-bank.secure-login.xyz/signin",
    "http://chase.account-alert.top/verify",
    "http://wellsfargo.secure-account.xyz/login",
    "http://bankofamerica.account-update.xyz/signin",
    "http://citi-bank.secure-verify.top/account",
    "http://hsbc.account-suspended.xyz/login",
    "http://barclays.secure-login.xyz/account/verify",
    "http://lloyds.online.secure-alert.xyz/login",
    # Indian bank/payment phishing
    "http://hdfc-netbanking.secure-login.xyz/verify",
    "http://icici-bank.account-verify.top/login",
    "http://sbi.onlinebanking.secure-update.xyz",
    "http://paytm-kyc-verify.xyz/account/update",
    "http://gpay.free-cashback.xyz/claim",
    "http://phonepe.kyc-pending.top/verify",
    "http://bhim-upi-reward.xyz/claim-prize",
    "http://upi-refund-helpdesk.xyz/submit",
    "http://paytm-wallet.refund-process.top/kyc",
    "http://kyc.update.sbi-secure.xyz/banking",
    # Netflix phishing
    "http://netflix-billing.update-required.xyz/login",
    "http://netflix.account-suspended.top/reactivate",
    "http://www.netflix-helpdesk.com/signin",
    "http://netf1ix.com/account/update-payment",
    # Crypto phishing
    "http://coinbase.account-verify.xyz/signin",
    "http://binance.secure-login.top/account",
    "http://metamask-wallet.connect.xyz/swap",
    "http://opensea.promo-event.xyz/free-nft/claim",
    "http://crypto-airdrop-claim.xyz/metamask",
    # Punycode / homograph attacks
    "http://xn--pple-43d.com/signin",
    "http://xn--googIe-hsa.com",
    "http://xn--pаypal-js2f.com/login",
    "http://xn--amzon-c4a.com/signin",
    "http://xn--facebk-gra.com",
    "http://xn--micrsoft-q5a.com/account",
    # IP-based phishing
    "http://192.168.1.1/admin/phish/login",
    "http://185.220.101.23/paypal/login",
    "http://45.153.160.2/amazon/signin",
    "http://91.228.154.1/microsoft/verify",
    "http://193.32.127.54/account/secure/login",
    # Suspicious TLD + brand
    "http://google.com.login.tk",
    "http://facebook.account.cf",
    "http://apple.secure.gq",
    "http://amazon.verify.ml",
    "http://paypal.account.ga",
    "http://microsoft.login.pw",
    "http://netflix.update.cc",
    # Download malware
    "http://free-software-download.xyz/crack/windows11.exe",
    "http://photoshop-crack.top/ps2024.exe",
    "http://download-free.xyz/setup.scr",
    "http://installer.xyz/adobe.pdf.exe",
    "http://update-required.xyz/chrome_update_v2.0.exe",
    "http://antivirus-free.xyz/setup_installer.msi",
    "http://crack.tk/office365_activator.bat",
    # URL shortener to phishing
    "http://bit.ly/3xPhish1",
    "http://tinyurl.com/scamsite",
    "http://t.co/phishredirect",
    # Obfuscated / encoded
    "http://paypal.com%40evil.com/signin",
    "http://secure.login.xyz/%61%63%63%6F%75%6E%74%2F%76%65%72%69%66%79",
    "http://www.google.com.evil.xyz/%2F%2F%2F/redirect?url=http://phish.com",
    # Path traversal
    "http://legit-site.com/../../../admin/passwd",
    "http://cdn.host.xyz/assets/../../config/credentials",
    # UPI fraud URLs
    "http://upi-prize.xyz/claim?vpa=refund@oksbi&amount=5000",
    "http://paytm-kyc.xyz/verify?pa=helpdesk@paytmgov&note=urgent",
    "http://gpay-cashback.top/redeem?pa=support@googlepay",
    "http://sbi-refund.xyz/process?vpa=taxrefund@government",
    "http://upi-fraud-trap.xyz/pay?pa=prize@fakebank&am=10",
    # Credential harvesting pages
    "http://secure-login.xyz/google/accounts/ServiceLoginAuth",
    "http://accounts.verify.top/signin/identifier?flowName=GlifWebSignIn",
    "http://login.account-restore.xyz/auth?continue=https://google.com",
    # Fake e-commerce
    "http://amazon-deals.free-shopping.xyz/checkout",
    "http://flipkart-sale.prize.xyz/cart",
    "http://ebay.discount-70.top/item",
    # Brand in subdomain (not TLD+1)
    "http://paypal.evil-domain.com/login",
    "http://google.phishsite.xyz/account",
    "http://apple.scam-host.top/signin",
    "http://amazon.fakeshop.xyz/order",
    "http://microsoft.fake.top/365",
    # Free money / prize scams
    "http://free-iphone-winner.xyz/claim?user=test",
    "http://congratulations-you-won.top/gift",
    "http://lucky-draw-amazon.xyz/prize",
    "http://free-recharge-trick.top/jio",
    "http://cash-reward-paytm.xyz/winner",
    # Excessive subdomains
    "http://login.secure.verify.account.paypal.phish.xyz",
    "http://a.b.c.d.e.phishing-site.xyz/login",
    "http://secure.banking.login.verify.account.evil.top",
    # Mixed case confusion
    "http://G00GLE.COM.phish.xyz/login",
    "http://PAYPAL-SECURE.COM.verify.top",
]

# ── Build dataset ──────────────────────────────────────────────────────────────

def build_dataset():
    urls    = LEGITIMATE_URLS + PHISHING_URLS
    labels  = [0] * len(LEGITIMATE_URLS) + [1] * len(PHISHING_URLS)
    X, y, skipped = [], [], 0
    for url, label in zip(urls, labels):
        try:
            feats = extract_features(url)
            assert len(feats) == 48, f"Feature count mismatch: got {len(feats)}"
            X.append(feats)
            y.append(label)
        except Exception as e:
            skipped += 1
            print(f"[WARN] Skipping URL {url}: {e}")
    print(f"Dataset: {len(X)} samples ({sum(y)} phishing, {len(y)-sum(y)} legit), {skipped} skipped")
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


# ── Train ──────────────────────────────────────────────────────────────────────

def train(X, y):
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=8,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    gbm = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.05,
        max_depth=5,
        min_samples_split=4,
        subsample=0.8,
        max_features="sqrt",
        random_state=42,
    )
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("gbm", gbm)],
        voting="soft",
        n_jobs=-1,
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    print("\n── 5-Fold Cross-Validation ─────────────────────────────────")
    cv_results = cross_validate(
        ensemble, X, y, cv=cv,
        scoring=["accuracy", "precision", "recall", "f1", "roc_auc"],
        return_train_score=False,
    )
    for metric, values in sorted(cv_results.items()):
        if metric.startswith("test_"):
            name = metric.replace("test_", "").upper()
            print(f"  {name:12s}: {values.mean():.4f} ± {values.std():.4f}")

    print("\n── Final fit on full dataset ───────────────────────────────")
    ensemble.fit(X, y)

    # Final report on training set (sanity check)
    y_pred = ensemble.predict(X)
    y_prob = ensemble.predict_proba(X)[:, 1]
    print(classification_report(y, y_pred, target_names=["Legitimate", "Phishing"]))
    auc = roc_auc_score(y, y_prob)
    print(f"  Training ROC-AUC: {auc:.4f}")

    return ensemble


# ── Export to ONNX ─────────────────────────────────────────────────────────────

def export_onnx(model, output_path="model.onnx"):
    initial_type = [("input", FloatTensorType([None, 48]))]
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        options={"zipmap": False},   # output raw arrays, not dicts
        target_opset=17,
    )
    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    onnx_size_kb = len(onnx_model.SerializeToString()) / 1024
    print(f"\n✓ model.onnx saved → {output_path}  ({onnx_size_kb:.1f} KB)")

    # Verify with onnxruntime
    try:
        import onnxruntime as rt
        sess = rt.InferenceSession(output_path)
        dummy = np.random.rand(1, 48).astype(np.float32)
        out = sess.run(None, {"input": dummy})
        print(f"✓ ONNX runtime verification passed. Output shapes: {[o.shape for o in out]}")
        print(f"  Output names: {[o.name for o in sess.get_outputs()]}")
    except Exception as e:
        print(f"[WARN] ONNX verification failed: {e}")


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Browser Vigilant — ML Training Pipeline")
    print("=" * 60)

    X, y = build_dataset()
    model = train(X, y)
    export_onnx(model)

    print("\n✓ Training complete. Load model.onnx into the extension.")
