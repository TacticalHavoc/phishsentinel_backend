import re
import socket
import subprocess
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse

import joblib
import pandas as pd
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Clean terminal and cloud log output
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

app = FastAPI()

# Enable clean cross-origin requests for the Chrome Extension
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

# Load original model pieces
try:
    model = joblib.load("XGBmodel.pkl")
    scaler = joblib.load("XGBscaler.pkl")
    encoder = joblib.load("XGBencoder.pkl")
    print("✅ Model components loaded successfully")
except Exception as e:
    print(f"❌ Error loading machine learning components: {e}")
    model = None
    scaler = None
    encoder = None


class URLInput(BaseModel):
    url: str


# --- 2. CORE UTILITY LOGIC (EXACT MATCH WITH CLI VERSION) ---
def is_site_real(hostname):
    try:
        socket.gethostbyname(hostname)
        return True, "Verified"
    except socket.gaierror:
        return False, "No DNS record found (Domain does not exist)."


def expand_url(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
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


# --- 3. FEATURE EXTRACTION (EXACT COPY FROM CLI VERSION) ---
def extract_features(input_url):
    try:
        is_shortened = (
            1
            if any(
                s in input_url.lower() for s in ["bit.ly", "t.co", "goo.gl", "tinyurl"]
            )
            else 0
        )

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
            1,  # dns_record
            final_url.lower().startswith("https"),  # Keep as boolean for now
        ]
        return features, final_url  # Return both like CLI version
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return [0] * 27, input_url


# --- 4. FASTAPI APP ROUTE (WITH EXACT CLI PREPROCESSING) ---
@app.post("/predict")
def predict(data: URLInput):
    # Check if model components are loaded
    if model is None or scaler is None or encoder is None:
        raise HTTPException(
            status_code=503,
            detail="Model components not loaded. Please check model files.",
        )

    url = data.url.strip()
    if not url.startswith("http"):
        url = "http://" + url

    initial_host = urlparse(url).netloc
    exists, msg = is_site_real(initial_host)

    # Immediately block domains lacking an active DNS structure
    if not exists:
        return {"is_phishing": True, "confidence": 100.0, "message": f"Blocked: {msg}"}

    try:
        # Extract features EXACTLY like CLI version
        raw_vals, final_destination = extract_features(url)

        # Apply encoder EXACTLY like CLI version
        raw_vals[26] = encoder.transform([raw_vals[26]])[0]

        # Create DataFrame EXACTLY like CLI version
        input_df = pd.DataFrame([raw_vals], columns=FEATURE_NAMES)
        scaled_data = scaler.transform(input_df)

        # Wrap scaled data back into a DataFrame (like CLI version for consistency)
        scaled_df = pd.DataFrame(scaled_data, columns=FEATURE_NAMES)

        # Make prediction EXACTLY like CLI version
        pred = model.predict(scaled_df)[0]
        prob = model.predict_proba(scaled_df)[0]

        # Convert numpy types to Python native types for JSON serialization
        is_phishing = bool(pred == 1)  # FIXED: Convert numpy.bool to Python bool
        confidence = float(
            prob[pred] * 100
        )  # Already float, but ensure it's Python float
        result_label = "PHISHING" if is_phishing else "LEGITIMATE"

        # Log details for debugging
        print(f"\n{'=' * 50}")
        print(f"URL: {url}")
        print(f"Final destination: {final_destination}")
        print(f"RESULT: {result_label}")
        print(f"CONFIDENCE: {confidence:.2f}%")
        print(f"{'=' * 50}\n")

        return {
            "is_phishing": is_phishing,  # FIXED: Now it's a Python bool
            "confidence": confidence,
            "final_url": final_destination,
            "prediction_text": result_label,
        }

    except Exception as e:
        print(f"Prediction error: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# --- 5. HEALTH CHECK ENDPOINT ---
@app.get("/health")
def health_check():
    return {
        "status": "healthy" if model is not None else "unhealthy",
        "model_loaded": model is not None,
        "scaler_loaded": scaler is not None,
        "encoder_loaded": encoder is not None,
    }


# --- 6. ROOT ENDPOINT ---
@app.get("/")
def root():
    return {
        "message": "Phishing Detection API (CLI-compatible version)",
        "endpoints": {
            "POST /predict": "Analyze a URL for phishing",
            "GET /health": "Check API health",
        },
    }


if __name__ == "__main__":
    import uvicorn

    print("\n🚀 Starting Phishing Detection API (CLI-Compatible)...")
    print("📡 Server running at http://0.0.0.0:8000")
    print(
        "🔍 Test with: curl -X POST http://localhost:8000/predict -H 'Content-Type: application/json' -d '{\"url\": \"https://example.com\"}'\n"
    )
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")