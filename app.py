import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
import socket
import re
from pathlib import Path
import base64

from pathlib import Path
from urllib.parse import urlparse
from tensorflow.keras.models import load_model


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="centered"
)



# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_ann_model.keras"
SCALER_PATH = BASE_DIR / "scaler.pkl"
FEATURE_PATH = BASE_DIR / "feature_names.json"
# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_resources():

    model = load_model(MODEL_PATH)

    scaler = joblib.load(SCALER_PATH)

    with open(FEATURE_PATH, "r") as file:
        feature_names = json.load(file)

    return model, scaler, feature_names


try:
    model, scaler, feature_names = load_resources()

except Exception as e:

    st.error("❌ Model files could not be loaded.")
    st.write(str(e))
    st.stop()


# ============================================================
# URL VALIDATION
# ============================================================

def normalize_url(url):

    url = url.strip()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def is_valid_url(url):

    try:

        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"]:
            return False

        if not parsed.netloc:
            return False

        return True

    except Exception:
        return False


# ============================================================
# URL FEATURES
# ============================================================

def check_ip_address(url):

    try:

        hostname = urlparse(url).hostname

        if not hostname:
            return 1

        socket.inet_aton(hostname)

        return 1

    except Exception:

        return -1


def url_length(url):

    length = len(url)

    if length < 54:
        return -1

    elif length <= 75:
        return 0

    else:
        return 1


def shortening_service(url):

    services = [
        "bit.ly",
        "goo.gl",
        "tinyurl.com",
        "ow.ly",
        "t.co",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "cutt.ly",
        "tiny.cc",
        "shorturl.at"
    ]

    url_lower = url.lower()

    for service in services:

        if service in url_lower:
            return 1

    return -1


def at_symbol(url):

    return 1 if "@" in url else -1


def double_slash_redirecting(url):

    try:

        if url.find("//", 8) != -1:
            return 1

        return -1

    except Exception:

        return -1


def prefix_suffix(url):

    hostname = urlparse(url).hostname or ""

    return 1 if "-" in hostname else -1


def sub_domain(url):

    hostname = urlparse(url).hostname or ""

    parts = hostname.split(".")

    if len(parts) <= 2:
        return -1

    elif len(parts) == 3:
        return 0

    else:
        return 1


def ssl_state(url):

    return -1 if url.lower().startswith("https://") else 1


def domain_registration_length(url):

    return 0


def favicon_feature(url):

    return 0


def port_feature(url):

    try:

        parsed = urlparse(url)

        if parsed.port is None:
            return -1

        if parsed.port in [80, 443]:
            return -1

        return 1

    except Exception:

        return 1


def https_token(url):

    hostname = urlparse(url).hostname or ""

    return 1 if "https" in hostname.lower() else -1


def request_url(url):

    return 0


def url_of_anchor(url):

    return 0


def links_in_tags(url):

    return 0


def sfh(url):

    return 0


def submitting_to_email(url):

    return 1 if "mailto:" in url.lower() else -1


def abnormal_url(url):

    parsed = urlparse(url)

    if not parsed.hostname:
        return 1

    return -1


def redirect_feature(url):

    parsed = urlparse(url)

    return 1 if "//" in parsed.path else -1


def mouseover(url):

    return -1


def right_click(url):

    return -1


def popup_window(url):

    return -1


def iframe(url):

    return -1


def age_of_domain(url):

    return 0


def dns_record(url):

    try:

        hostname = urlparse(url).hostname

        if not hostname:
            return 1

        socket.gethostbyname(hostname)

        return -1

    except Exception:

        return 1


def web_traffic(url):

    return 0


def page_rank(url):

    return 0


def google_index(url):

    return 0


def links_pointing_to_page(url):

    return 0


def statistical_report(url):

    return 0


# ============================================================
# EXTRA SECURITY CHECKS
# ============================================================

def suspicious_url_score(url):

    score = 0

    parsed = urlparse(url)

    hostname = (parsed.hostname or "").lower()

    full_url = url.lower()

    # --------------------------------------------------------
    # IP address
    # --------------------------------------------------------

    if check_ip_address(url) == 1:
        score += 3

    # --------------------------------------------------------
    # HTTP instead of HTTPS
    # --------------------------------------------------------

    if not full_url.startswith("https://"):
        score += 2

    # --------------------------------------------------------
    # @ symbol
    # --------------------------------------------------------

    if "@" in url:
        score += 3

    # --------------------------------------------------------
    # Very long URL
    # --------------------------------------------------------

    if len(url) > 100:
        score += 1

    if len(url) > 180:
        score += 2

    # --------------------------------------------------------
    # Suspicious number of subdomains
    # --------------------------------------------------------

    parts = hostname.split(".")

    if len(parts) >= 4:
        score += 2

    # --------------------------------------------------------
    # Hyphenated suspicious hostname
    # --------------------------------------------------------

    if "-" in hostname:
        score += 1

    # --------------------------------------------------------
    # URL shortener
    # --------------------------------------------------------

    if shortening_service(url) == 1:
        score += 2

    # --------------------------------------------------------
    # Suspicious words
    # --------------------------------------------------------

    suspicious_words = [

        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "secure",
        "security",
        "update",
        "confirm",
        "confirmation",
        "password",
        "credential",
        "wallet",
        "payment",
        "bank",
        "banking",
        "recover",
        "unlock",
        "authenticate",
        "webscr",
        "bonus",
        "freegift",
        "claim",
        "urgent"
    ]

    keyword_count = 0

    for word in suspicious_words:

        if word in full_url:
            keyword_count += 1

    if keyword_count >= 3:
        score += 4

    elif keyword_count == 2:
        score += 2

    elif keyword_count == 1:
        score += 1

    # --------------------------------------------------------
    # Suspicious separators
    # --------------------------------------------------------

    if full_url.count("-") >= 3:
        score += 2

    if full_url.count(".") >= 5:
        score += 2

    # --------------------------------------------------------
    # Encoded characters
    # --------------------------------------------------------

    if "%40" in full_url:
        score += 2

    # --------------------------------------------------------
    # Multiple @ / query tricks
    # --------------------------------------------------------

    if url.count("@") >= 1:
        score += 2

    return score


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(url):

    return {

        "index": 0,

        "having_IPhaving_IP_Address":
            check_ip_address(url),

        "URLURL_Length":
            url_length(url),

        "Shortining_Service":
            shortening_service(url),

        "having_At_Symbol":
            at_symbol(url),

        "double_slash_redirecting":
            double_slash_redirecting(url),

        "Prefix_Suffix":
            prefix_suffix(url),

        "having_Sub_Domain":
            sub_domain(url),

        "SSLfinal_State":
            ssl_state(url),

        "Domain_registeration_length":
            domain_registration_length(url),

        "Favicon":
            favicon_feature(url),

        "port":
            port_feature(url),

        "HTTPS_token":
            https_token(url),

        "Request_URL":
            request_url(url),

        "URL_of_Anchor":
            url_of_anchor(url),

        "Links_in_tags":
            links_in_tags(url),

        "SFH":
            sfh(url),

        "Submitting_to_email":
            submitting_to_email(url),

        "Abnormal_URL":
            abnormal_url(url),

        "Redirect":
            redirect_feature(url),

        "on_mouseover":
            mouseover(url),

        "RightClick":
            right_click(url),

        "popUpWidnow":
            popup_window(url),

        "Iframe":
            iframe(url),

        "age_of_domain":
            age_of_domain(url),

        "DNSRecord":
            dns_record(url),

        "web_traffic":
            web_traffic(url),

        "Page_Rank":
            page_rank(url),

        "Google_Index":
            google_index(url),

        "Links_pointing_to_page":
            links_pointing_to_page(url),

        "Statistical_report":
            statistical_report(url)
    }


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ PhishGuard AI")

st.write(
    "Artificial Neural Network based phishing website detection system."
)

st.info(
    "Enter a website URL below to check whether it appears SAFE, "
    "SUSPICIOUS, or UNSAFE."
)


# ============================================================
# URL INPUT
# ============================================================

st.subheader("🌐 Website URL")

url_input = st.text_input(
    "Enter URL",
    placeholder="https://example.com",
    label_visibility="collapsed"
)


# ============================================================
# CHECK BUTTON
# ============================================================

if st.button("🔍 Check Website", use_container_width=True):

    if not url_input.strip():

        st.warning("⚠️ Please enter a website URL.")

        st.stop()

    url = normalize_url(url_input)

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    if not is_valid_url(url):

        st.error("❌ Invalid URL")

        st.write(
            "Please enter a valid URL such as https://example.com"
        )

        st.stop()

    # --------------------------------------------------------
    # Extract features
    # --------------------------------------------------------

    try:

        extracted = extract_features(url)

        input_data = []

        for feature in feature_names:

            input_data.append(
                extracted.get(feature, 0)
            )

        input_df = pd.DataFrame(
            [input_data],
            columns=feature_names
        )

        # ----------------------------------------------------
        # Scale
        # ----------------------------------------------------

        scaled_input = scaler.transform(input_df)

        # ----------------------------------------------------
        # ANN prediction
        # ----------------------------------------------------

        output = model.predict(
            scaled_input,
            verbose=0
        )

        # ----------------------------------------------------
        # ANN probability
        # ----------------------------------------------------

        if output.shape[1] == 1:

            ann_probability = float(output[0][0])

            if ann_probability >= 0.5:

                ann_prediction = 1
                ann_confidence = ann_probability

            else:

                ann_prediction = 0
                ann_confidence = 1 - ann_probability

        else:

            ann_prediction = int(
                np.argmax(output, axis=1)[0]
            )

            ann_confidence = float(
                np.max(output, axis=1)[0]
            )

        # ----------------------------------------------------
        # Security score
        # ----------------------------------------------------

        security_score = suspicious_url_score(url)

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        dns_problem = (
            dns_record(url) == 1
        )

        # ====================================================
        # FINAL DECISION
        # ====================================================

        # Strong suspicious URL signals
        if security_score >= 7:

            final_result = "UNSAFE"

            final_confidence = min(
                99.0,
                max(
                    85.0,
                    security_score * 10
                )
            )

        # Non-existing domain
        elif dns_problem and security_score >= 3:

            final_result = "UNSAFE"

            final_confidence = 90.0

        # ANN says phishing + suspicious signals
        elif ann_prediction == 1 and security_score >= 2:

            final_result = "UNSAFE"

            final_confidence = max(
                ann_confidence * 100,
                75.0
            )

        # Moderate suspicious signals
        elif security_score >= 3:

            final_result = "SUSPICIOUS"

            final_confidence = 70.0

        # ANN phishing with no strong URL evidence
        elif ann_prediction == 1:

            final_result = "SUSPICIOUS"

            final_confidence = (
                ann_confidence * 100
            )

        else:

            final_result = "SAFE"

            final_confidence = (
                ann_confidence * 100
            )

        # ====================================================
        # DISPLAY RESULT
        # ====================================================

        st.divider()

        if final_result == "UNSAFE":

            st.error(
                "🔴 UNSAFE / PHISHING WEBSITE"
            )

            st.write(
                "⚠️ This URL contains characteristics "
                "associated with phishing or unsafe websites."
            )

        elif final_result == "SUSPICIOUS":

            st.warning(
                "🟠 SUSPICIOUS WEBSITE"
            )

            st.write(
                "⚠️ This URL contains some suspicious "
                "characteristics. Avoid entering sensitive information."
            )

        else:

            st.success(
                "🟢 SAFE / LEGITIMATE WEBSITE"
            )

            st.write(
                "✅ No major phishing characteristics were detected."
            )

        # ====================================================
        # CONFIDENCE
        # ====================================================

        st.subheader("📊 Detection Confidence")

        confidence_value = min(
            max(final_confidence, 0.0),
            100.0
        )

        st.metric(
            "Confidence",
            f"{confidence_value:.2f}%"
        )

        st.progress(
            int(confidence_value)
        )

        # ====================================================
        # SECURITY SCORE
        # ====================================================

        st.subheader("🛡️ Security Analysis")

        st.write(
            f"Suspicious URL indicators detected: "
            f"**{security_score}**"
        )

        if security_score == 0:

            st.success(
                "No obvious URL-level suspicious indicators."
            )

        elif security_score <= 2:

            st.info(
                "Few suspicious URL indicators were detected."
            )

        elif security_score <= 5:

            st.warning(
                "Several suspicious URL indicators were detected."
            )

        else:

            st.error(
                "Multiple strong suspicious URL indicators were detected."
            )

        # ====================================================
        # ANALYZED URL
        # ====================================================

        st.subheader("🔗 Analyzed Website")

        st.code(
            url,
            language=None
        )

        # ====================================================
        # ANN INFORMATION
        # ====================================================

        with st.expander("🤖 ANN Model Information"):

            st.write(
                "Model: Artificial Neural Network"
            )

            st.write(
                f"ANN prediction: {ann_prediction}"
            )

            st.write(
                f"ANN confidence: {ann_confidence * 100:.2f}%"
            )

            st.write(
                f"URL security score: {security_score}"
            )

    except Exception as e:

        st.error(
            "❌ Prediction failed."
        )

        st.write(
            str(e)
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown("""
<style>

.stApp {
    background: linear-gradient(135deg, #07111f, #0b1f3a, #102a43);
}

/* Main text */
h1, h2, h3, h4, p, label {
    color: #ffffff !important;
}

/* URL input */
.stTextInput input {
    background-color: #ffffff !important;
    color: #111111 !important;
    border: 2px solid #3b82f6 !important;
    border-radius: 10px !important;
}

/* SAFE result box */
.safe-box {
    background-color: #d1fae5 !important;
    color: #065f46 !important;
    padding: 20px;
    border-radius: 14px;
    border: 2px solid #10b981;
    margin-top: 15px;
}

.safe-box h2,
.safe-box p,
.safe-box div {
    color: #065f46 !important;
}

/* SUSPICIOUS result box */
.suspicious-box {
    background-color: #fef3c7 !important;
    color: #92400e !important;
    padding: 20px;
    border-radius: 14px;
    border: 2px solid #f59e0b;
    margin-top: 15px;
}

/* UNSAFE result box */
.unsafe-box {
    background-color: #fee2e2 !important;
    color: #991b1b !important;
    padding: 20px;
    border-radius: 14px;
    border: 2px solid #ef4444;
    margin-top: 15px;
}

/* Confidence card */
.confidence-card {
    background-color: #ffffff !important;
    color: #111827 !important;
    padding: 20px;
    border-radius: 14px;
    border: 2px solid #3b82f6;
    margin-top: 15px;
}

.confidence-card h3,
.confidence-card p,
.confidence-card div,
.confidence-card span {
    color: #111827 !important;
}

/* Button */
.stButton button {
    background-color: #2563eb !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    font-weight: bold;
}

.stButton button:hover {
    background-color: #1d4ed8 !important;
}

</style>
""", unsafe_allow_html=True)
