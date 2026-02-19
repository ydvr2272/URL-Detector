import streamlit as st
import re
import pandas as pd
from urllib.parse import urlparse

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV


# ---------------- LOAD & TRAIN MODEL ----------------
@st.cache_resource
def load_model():

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

    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        max_features=20000
    )

    X_vec = vectorizer.fit_transform(X)

    base_lr = LogisticRegression(
        max_iter=500,
        solver="liblinear",
        class_weight="balanced"
    )

    model = CalibratedClassifierCV(base_lr, method='sigmoid')
    model.fit(X_vec, y)

    return vectorizer, model


vectorizer, model = load_model()


# ---------------- RULE FUNCTIONS ----------------
def has_ip(url):
    return bool(re.search(r"\d+\.\d+\.\d+\.\d+", url))


def too_many_special_chars(url):
    return len(re.findall(r"[^\w]", url)) > 10


GOV_TLDS = (".gov", ".gov.in", ".nic.in", ".edu", ".mil")

TRUSTED_DOMAINS = (
    "google.com",
    "linkedin.com",
    "wikipedia.org",
    "youtube.com",
    "amazon.in",
    "hotstar.com"
)


# ---------------- UI ----------------
st.title("🔍 URL Safety Checker")
st.write("Check whether a URL is Safe, Suspicious, or Malicious")

url = st.text_input("Enter URL")

if st.button("Check URL"):

    if not url:
        st.error("Please enter a URL")
    else:

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if domain == "":
            domain = url.lower()

        clean_domain = domain.replace("www.", "")
        base_domain = clean_domain.split(":")[0]

        if base_domain.endswith(GOV_TLDS):
            st.success("SAFE ✅ (Government Domain)")

        elif any(base_domain == td or base_domain.endswith("." + td) for td in TRUSTED_DOMAINS):
            st.success("SAFE ✅ (Trusted Domain)")

        elif has_ip(url):
            st.warning("SUSPICIOUS ⚠️ (IP Address Detected)")

        elif too_many_special_chars(url):
            st.warning("SUSPICIOUS ⚠️ (Too Many Special Characters)")

        else:
            url_vec = vectorizer.transform([url])
            malicious_prob = model.predict_proba(url_vec)[0][1] * 100

            st.write(f"Malicious Probability: {malicious_prob:.2f}%")

            if malicious_prob < 30:
                st.success("SAFE ✅")
            elif malicious_prob <= 50:
                st.warning("SUSPICIOUS ⚠️")
            else:
                st.error("MALICIOUS 🚨")
import joblib

joblib.dump(lr_model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("\n✅ Model Saved Successfully!")

