# Script to test on terminal level
# Run python3 xgbpredict.py


import re
import socket
import subprocess
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse
import joblib
import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup

# Clean terminal output
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- 1. CONFIGURATION ---
FEATURE_NAMES = [
    "length_url",
    "length_hostname",
    "ip",
    "nb_hyphens",
    "nb_dots",
    "nb_at",
    "nb_and",
    "nb_underscore",
    "nb_percent",
    "nb_slash",
    "nb_colon",
    "nb_comma",
    "port",
    "tld_in_path",
    "tld_in_subdomain",
    "shortening_service",
    "path_extension",
    "nb_redirection",
    "nb_external_redirection",
    "login_form",
    "iframe",
    "domain_with_copyright",
    "whois_registered_domain",
    "domain_registration_length",
    "domain_age",
    "dns_record",
    "has_https",
]


# --- 2. LOGIC FUNCTIONS ---
def is_site_real(hostname):
    try:
        socket.gethostbyname(hostname)
        return True, "Verified"
    except socket.gaierror:
        return False, "No DNS record found (Domain does not exist)."


def expand_url(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        # Following redirects to the very end
        response = requests.get(url, allow_redirects=True, timeout=5, headers=headers)
        return response.url
    except:
        return url


def get_whois_features(domain):
    try:
        result = subprocess.check_output(["whois", domain], timeout=5).decode(
            errors="ignore"
        )
        registered = 1 if "Domain Name" in result else 0
        c_match = re.search(r"Creation Date:\s*(.+)", result)
        e_match = re.search(r"Expiry Date:\s*(.+)|Registry Expiry Date:\s*(.+)", result)

        if not c_match or not e_match:
            return registered, 0, 0

        created = datetime.strptime(c_match.group(1)[:10], "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
        expires = datetime.strptime(
            (e_match.group(1) or e_match.group(2))[:10], "%Y-%m-%d"
        ).replace(tzinfo=timezone.utc)
        today = datetime.now(timezone.utc)

        return registered, (expires - today).days, (today - created).days
    except:
        return 0, 0, 0


# --- 3. FEATURE EXTRACTION ---
def extract_features(input_url):
    try:
        # Detect shortener on the INPUT URL
        is_shortened = (
            1
            if any(
                s in input_url.lower() for s in ["bit.ly", "t.co", "goo.gl", "tinyurl"]
            )
            else 0
        )

        # Follow the link to the actual site
        final_url = expand_url(input_url)
        parsed = urlparse(final_url)
        hostname = parsed.netloc
        path = parsed.path
        domain = ".".join(hostname.split(".")[-2:]) if "." in hostname else hostname
        tld = hostname.split(".")[-1] if "." in hostname else ""

        try:
            res = requests.get(
                final_url, timeout=4, headers={"User-Agent": "Mozilla/5.0"}
            )
            html, redirects = res.text, len(res.history)
            ext_redirect = 1 if urlparse(res.url).netloc != hostname else 0
        except:
            html, redirects, ext_redirect = "", 0, 0

        soup = BeautifulSoup(html, "html.parser")
        reg, reg_len, age = get_whois_features(domain)

        # Build feature list based on the FINAL destination + original shortener flag
        features = [
            len(final_url),
            len(hostname),
            (1 if re.match(r"\d+\.\d+", hostname) else 0),
            final_url.count("-"),
            final_url.count("."),
            final_url.count("@"),
            final_url.count("&"),
            final_url.count("_"),
            final_url.count("%"),
            final_url.count("/"),
            final_url.count(":"),
            final_url.count(","),
            (parsed.port if parsed.port else 0),
            (1 if tld in path else 0),
            (1 if tld in hostname.split(".")[:-2] else 0),
            is_shortened,
            (
                1
                if any(
                    final_url.lower().endswith(e) for e in ["php", "exe", "zip", "rar"]
                )
                else 0
            ),
            redirects,
            ext_redirect,
            (1 if soup.find_all("form") else 0),
            (1 if soup.find_all("iframe") else 0),
            (1 if "copyright" in html.lower() else 0),
            reg,
            reg_len,
            age,
            1,
            final_url.lower().startswith("https"),
        ]
        return features, final_url
    except:
        return [0] * 27, input_url


# --- 4. EXECUTION ---
if __name__ == "__main__":
    try:
        model = joblib.load("XGBmodel.pkl")
        scaler = joblib.load("XGBscaler.pkl")
        encoder = joblib.load("XGBencoder.pkl")
    except Exception as e:
        print(f"Error loading model files: {e}")
        exit()

    url_in = input("\nEnter URL: ").strip()
    if not url_in.startswith("http"):
        url_in = "http://" + url_in

    # Gatekeeper
    initial_host = urlparse(url_in).netloc
    exists, msg = is_site_real(initial_host)

    if not exists:
        print(f"\nBLOCKING: {msg}")
    else:
        print("[*] Following redirects to final destination...")
        raw_vals, final_destination = extract_features(url_in)

        # Apply Encoder
        raw_vals[26] = encoder.transform([raw_vals[26]])[0]

        # XGBoost Prediction (Purely ML)
        input_df = pd.DataFrame([raw_vals], columns=FEATURE_NAMES)
        scaled_data = scaler.transform(input_df)

        # Get raw probability
        pred = model.predict(scaled_data)[0]
        prob = model.predict_proba(scaled_data)[0]
        result_label = "PHISHING" if pred == 1 else "LEGITIMATE"
        confidence = prob[pred] * 100

        # --- OUTPUT ---
        print(f"\n{'=' * 50}")
        print(f"PURE MODEL RESULT: {result_label}")
        print(f"MODEL CONFIDENCE: {confidence:.2f}%")
        print(f"{'=' * 50}")

        print("\nTECHNICAL DATA:")
        print(f"• Redirected to: {final_destination}")
        print(f"• Shortener Flag: {raw_vals[15]}")

        print("\nTOP INFLUENCING FEATURES:")
        importances = model.feature_importances_
        for i in np.argsort(importances)[::-1][:5]:
            print(f"-> {FEATURE_NAMES[i]:25} | Value: {raw_vals[i]}")
