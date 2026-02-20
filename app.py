import streamlit as st
import joblib
import re
from urllib.parse import urlparse

st.set_page_config(page_title="URL Detector", page_icon="🛡️")

st.title("🛡️ Malicious URL Detector")

@st.cache_resource
def load_model():
    vectorizer = joblib.load("vectorizer.pkl")
    model = joblib.load("model.pkl")
    return vectorizer, model

vectorizer, model = load_model()

GOV_TLDS = (".gov", ".gov.in", ".nic.in", ".edu", ".mil")

TRUSTED_DOMAINS = (
    "google.com",
    "youtube.com",
    "linkedin.com",
    "wikipedia.org",
    "amazon.in",
    "hotstar.com",
    "paytm.com",
    "phonepe.com",
    "github.com"
)

def has_ip(url):
    return bool(re.search(r"\d+\.\d+\.\d+\.\d+", url))

def too_many_special_chars(url):
    return len(re.findall(r"[^\w]", url)) > 10


url = st.text_input("Enter URL")

if st.button("Check URL"):

    if not url:
        st.warning("Enter a URL")
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
