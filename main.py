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
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Clean terminal and log output
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

app = FastAPI()

# Allows your Chrome Extension to communicate with this script safely
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

# Load your ML model components
try:
    model = joblib.load("XGBmodel.pkl")
    scaler = joblib.load("XGBscaler.pkl")
    encoder = joblib.load("XGBencoder.pkl")
except Exception as e:
    print(f"Error loading model files: {e}")

class URLInput(BaseModel):
    url: str


# --- 2. LOGIC FUNCTIONS (FROM ORIGINAL SCRIPT) ---
def is_site_real(hostname):
    try:
        socket.gethostbyname(hostname)
        return True, "Verified"
    except socket.gaierror:
        return False, "No DNS record found (Domain does not exist)."


def expand_url(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(
            url, allow_redirects=True, timeout=5, headers=headers
        )
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
        e_match = re.search(
            r"Expiry Date:\s*(.+)|Registry Expiry Date:\s*(.+)", result
        )

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


# --- 3. FEATURE EXTRACTION (EXACT TERMINAL ALIGNMENT) ---
def extract_features(input_url):
    try:
        is_shortened = (
            1
            if any(
                s in input_url.lower()
                for s in ["bit.ly", "t.co", "goo.gl", "tinyurl"]
            )
            else 0
        )

        final_url = expand_url(input_url)
        parsed = urlparse(final_url)
        hostname = parsed.netloc
        path = parsed.path
        domain = (
            ".".join(hostname.split(".")[-2:]) if "." in hostname else hostname
        )
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
                    final_url.lower().endswith(e)
                    for e in ["php", "exe", "zip", "rar"]
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
            final_url.lower().startswith("https"),  # Returns raw native Boolean type for the encoder
        ]
        return features
    except:
        return [0] * 27


# --- 4. ENDPOINT FOR PREDICTION ---
@app.post("/predict")
def predict(data: URLInput):
    url = data.url.strip()
    if not url.startswith("http"):
        url = "http://" + url

    initial_host = urlparse(url).netloc
    exists, msg = is_site_real(initial_host)

    # Fast-track dead/unregistered malicious targets
    if not exists:
        return {"is_phishing": True, "confidence": 100.0}

    try:
        # 1. Extract raw feature matrix matching training structures exactly
        raw_vals = extract_features(url)

        # 2. Match the exact boolean type label mapping logic used in terminal execution
        raw_vals[26] = encoder.transform([raw_vals[26]])[0]

        # 3. Shape data frames, scale, and pass into model
        input_df = pd.DataFrame([raw_vals], columns=FEATURE_NAMES)
        scaled_data = scaler.transform(input_df)
        scaled_df = pd.DataFrame(scaled_data, columns=FEATURE_NAMES)

        prediction = int(model.predict(scaled_df)[0])
        probabilities = model.predict_proba(scaled_df)[0]
        confidence = float(probabilities[prediction] * 100)

        return {"is_phishing": prediction == 1, "confidence": confidence}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))