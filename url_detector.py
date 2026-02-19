# ==========================================
# URL MALICIOUS DETECTION SYSTEM (RUNNING)
# ==========================================


from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV

import pandas as pd
import re
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score


print("Loading dataset...")

data = pd.read_csv("malicious_urls.csv")

data["label"] = data["type"].map({
    "benign": 0,
    "phishing": 1,
    "defacement": 1,
    "malware": 1
})

data = data.dropna(subset=["label"])

X = data["url"]
y = data["label"]

print("\nClass distribution:")
print(y.value_counts())


X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("\nVectorizing URLs...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    max_features=20000
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

print("\nTraining Logistic Regression...")

base_lr = LogisticRegression(
    max_iter=500,
    solver="liblinear",
    class_weight="balanced"
)

lr_model = CalibratedClassifierCV(base_lr, method='sigmoid')
lr_model.fit(X_train_vec, y_train)

lr_accuracy = accuracy_score(y_test, lr_model.predict(X_test_vec))

print(f"\nModel Accuracy: {lr_accuracy * 100:.2f}%")


GOV_TLDS = (".gov", ".gov.in", ".nic.in", ".edu", ".mil")

TRUSTED_DOMAINS = (
    "google.com",
    "youtube.com",
    "gmail.com",
    "maps.google.com",
    "drive.google.com",
    "docs.google.com",
    "meet.google.com",
    "google.co.in",
    "google.co.uk",
    "google.org",
    "googleusercontent.com",
    "gstatic.com",

    "amazon.com",
    "amazon.in",
    "amazon.co.uk",
    "amazonaws.com",

    "microsoft.com",
    "live.com",
    "outlook.com",
    "office.com",
    "onedrive.live.com",

    "apple.com",
    "icloud.com",

    "facebook.com",
    "fb.com",
    "messenger.com",
    "instagram.com",
    "whatsapp.com",
    "threads.net",

    "twitter.com",
    "x.com",

    "linkedin.com",
    "snapchat.com",
    "pinterest.com",
    "reddit.com",
    "quora.com",
    "tumblr.com",

    "netflix.com",
    "primevideo.com",
    "hotstar.com",
    "disneyplus.com",
    "spotify.com",
    "zee5.com",
    "sonyliv.com",

    "flipkart.com",
    "myntra.com",
    "ajio.com",
    "snapdeal.com",
    "meesho.com",
    "nykaa.com",

    "paytm.com",
    "phonepe.com",
    "upi.gov.in",
    "bhimupi.org.in",
    "razorpay.com",
    "instamojo.com",
    "paypal.com",

    "hdfcbank.com",
    "icicibank.com",
    "sbi.co.in",
    "axisbank.com",
    "bankofbaroda.in",
    "unionbankofindia.co.in",
    "canarabank.com",
    "pnbindia.in",
    "indusind.com",
    "kotak.com",

    "gov.in",
    "nic.in",
    "india.gov.in",
    "uidai.gov.in",
    "passportindia.gov.in",
    "incometax.gov.in",
    "gst.gov.in",
    "rbi.org.in",
    "sebi.gov.in",
    "epfindia.gov.in",
    "up.gov.in",
    "mp.gov.in",
    "cg.gov.in",
    "maharashtra.gov.in",
    "delhi.gov.in",
    "tamilnadu.gov.in",
    "karnataka.gov.in",
    "kerala.gov.in",

    "un.org",
    "who.int",
    "worldbank.org",
    "imf.org",
    "unesco.org",
    "nasa.gov",

    "wikipedia.org",
    "britannica.com",

    "coursera.org",
    "edx.org",
    "udemy.com",
    "khanacademy.org",
    "byjus.com",
    "unacademy.com",
    "vedantu.com",

    "stackoverflow.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "python.org",
    "oracle.com",
    "ibm.com",
    "intel.com",
    "nvidia.com",
    "adobe.com",
    "dropbox.com",

    "cloudflare.com",
    "akamai.com",
    "fastly.com",

    "cnn.com",
    "bbc.com",
    "reuters.com",
    "ndtv.com",
    "indiatoday.in",
    "timesofindia.indiatimes.com",
    "hindustantimes.com",
    "thehindu.com",
    "indianexpress.com",

    "airindia.com",
    "irctc.co.in",
    "makemytrip.com",
    "goibibo.com",
    "booking.com",
    "expedia.com",
    "oyo.com",

    "zoom.us",
    "skype.com",
    "teams.microsoft.com",
    "slack.com",

    "telegram.org",
    "signal.org",

    "medium.com",
    "substack.com",

    "canva.com",
    "figma.com",

    "tcs.com",
    "infosys.com",
    "wipro.com",
    "hcltech.com",
    "accenture.com",
    "cognizant.com",
    "deloitte.com",
    "pwc.com",
    "ey.com",
    "kpmg.com",

    "licindia.in",
    "policybazaar.com"
)


def has_ip(url):
    return bool(re.search(r"\d+\.\d+\.\d+\.\d+", url))


def too_many_special_chars(url):
    return len(re.findall(r"[^\w]", url)) > 10


print("\n----------------------------------")
print("URL CHECKER READY 🚀")
print("----------------------------------")

while True:

    url = input("\nEnter URL (or exit): ").strip()

    if url.lower() == "exit":
        print("Exiting 👋")
        break

    if not url:
        print("❌ No URL entered")
        continue

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if domain == "":
        domain = url.lower()

    clean_domain = domain.replace("www.", "")
    base_domain = clean_domain.split(":")[0]

    if base_domain.endswith(GOV_TLDS):
        print("Final Result: SAFE ✅ (Government Domain)")
        continue

    if any(base_domain == td or base_domain.endswith("." + td) for td in TRUSTED_DOMAINS):
        print("Final Result: SAFE ✅ (Trusted Domain)")
        continue

    if has_ip(url):
        print("Final Result: SUSPICIOUS ⚠️")
        print("Reason: IP Address Detected")
        continue

    if too_many_special_chars(url):
        print("Final Result: SUSPICIOUS ⚠️")
        print("Reason: Too Many Special Characters")
        continue

    url_vec = vectorizer.transform([url])
    malicious_prob = lr_model.predict_proba(url_vec)[0][1] * 100

    print(f"Malicious Probability: {malicious_prob:.2f}%")

    if malicious_prob < 30:
        print("Final Result: SAFE ✅")
    elif malicious_prob <= 50:
        print("Final Result: SUSPICIOUS ⚠️")
    else:
        print("Final Result: MALICIOUS 🚨")
