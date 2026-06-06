import re
import socket
import subprocess
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse
import logging

import joblib
import pandas as pd
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

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
PHISHING_THRESHOLD = 70.0  # Only classify as phishing if confidence > 70%
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
    logger.info("✅ Model components loaded successfully")
    logger.info(f"📊 Model type: {type(model).__name__}")
    logger.info(f"📊 Encoder classes: {encoder.classes_}")
except Exception as e:
    logger.error(f"❌ Error loading machine learning components: {e}")
    model = None
    scaler = None
    encoder = None


class URLInput(BaseModel):
    url: str


# --- 2. CORE UTILITY LOGIC ---
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
    except Exception as e:
        logger.debug(f"URL expansion failed for {url}: {e}")
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
    except Exception as e:
        logger.debug(f"WHOIS lookup failed for {domain}: {e}")
        return 0, 0, 0


# --- 3. FEATURE EXTRACTION ---
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
        except Exception as e:
            logger.debug(f"Failed to fetch {final_url}: {e}")
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
        return features, final_url
    except Exception as e:
        logger.error(f"Feature extraction error for {input_url}: {e}")
        return [0] * 27, input_url


# --- 4. FASTAPI APP ROUTE (FIXED CONFIDENCE CALCULATION) ---
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
        logger.warning(f"🚫 BLOCKED - No DNS: {url}")
        return {
            "is_phishing": True, 
            "confidence": 100.0, 
            "message": f"Blocked: {msg}",
            "prediction_text": "PHISHING"
        }

    try:
        # Extract features
        raw_vals, final_destination = extract_features(url)
        
        # Log key features for debugging
        logger.info(f"🔍 Analyzing: {url}")
        logger.info(f"   Final URL: {final_destination}")
        logger.info(f"   URL length: {raw_vals[0]}, Has HTTPS: {raw_vals[26]}")
        logger.info(f"   Redirects: {raw_vals[17]}, External redirects: {raw_vals[18]}")
        logger.info(f"   Forms: {raw_vals[19]}, IFrames: {raw_vals[20]}")
        logger.info(f"   Domain age: {raw_vals[24]} days, Registration length: {raw_vals[23]} days")
        logger.info(f"   Shortened: {raw_vals[15]}, Path extension: {raw_vals[16]}")

        # Apply encoder
        raw_vals[26] = encoder.transform([raw_vals[26]])[0]

        # Create DataFrame and scale
        input_df = pd.DataFrame([raw_vals], columns=FEATURE_NAMES)
        scaled_data = scaler.transform(input_df)
        scaled_df = pd.DataFrame(scaled_data, columns=FEATURE_NAMES)

        # Make prediction
        pred = model.predict(scaled_df)[0]
        prob = model.predict_proba(scaled_df)[0]

        # Convert numpy types to Python native types
        raw_is_phishing = bool(pred == 1)
        raw_confidence = float(prob[pred] * 100)  # Model's confidence in its prediction
        
        # FIXED: Apply threshold correctly WITHOUT inverting confidence
        if raw_is_phishing:
            # Model thinks it's phishing
            final_is_phishing = raw_confidence > PHISHING_THRESHOLD
            final_confidence = raw_confidence  # Confidence in PHISHING verdict
            result_label = "PHISHING" if final_is_phishing else "LEGITIMATE"
        else:
            # Model thinks it's legitimate
            final_is_phishing = False
            final_confidence = raw_confidence  # Confidence in LEGITIMATE verdict (NOT inverted!)
            result_label = "LEGITIMATE"
        
        # Comprehensive logging
        logger.info(f"{'='*60}")
        logger.info(f"📊 RAW RESULT: {'PHISHING' if raw_is_phishing else 'LEGITIMATE'} ({raw_confidence:.2f}%)")
        logger.info(f"🎯 FINAL RESULT: {result_label} ({final_confidence:.2f}%)")
        logger.info(f"⚙️  Threshold: {PHISHING_THRESHOLD}%")
        logger.info(f"🌐 URL: {url}")
        logger.info(f"🏁 Final destination: {final_destination}")
        logger.info(f"{'='*60}")

        return {
            "is_phishing": final_is_phishing,
            "confidence": final_confidence,
            "raw_confidence": raw_confidence,
            "final_url": final_destination,
            "prediction_text": result_label,
            "threshold_applied": PHISHING_THRESHOLD,
            "raw_prediction": "PHISHING" if raw_is_phishing else "LEGITIMATE"
        }

    except Exception as e:
        logger.error(f"❌ Prediction error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# --- 5. DEBUG ENDPOINT (For troubleshooting) ---
@app.post("/debug")
def debug_features(data: URLInput):
    """Debug endpoint to see raw feature values"""
    if model is None or scaler is None or encoder is None:
        raise HTTPException(
            status_code=503,
            detail="Model components not loaded. Please check model files.",
        )
    
    url = data.url.strip()
    if not url.startswith("http"):
        url = "http://" + url
    
    raw_vals, final_destination = extract_features(url)
    
    # Create feature dictionary
    features_dict = {}
    for i, (name, value) in enumerate(zip(FEATURE_NAMES, raw_vals)):
        features_dict[name] = value
    
    return {
        "url": url,
        "final_url": final_destination,
        "features": features_dict,
        "has_https_raw": raw_vals[26],
        "has_https_type": str(type(raw_vals[26])),
        "feature_count": len(raw_vals)
    }


# --- 6. HEALTH CHECK ENDPOINT ---
@app.get("/health")
def health_check():
    return {
        "status": "healthy" if model is not None else "unhealthy",
        "model_loaded": model is not None,
        "scaler_loaded": scaler is not None,
        "encoder_loaded": encoder is not None,
        "threshold": PHISHING_THRESHOLD,
        "feature_count": len(FEATURE_NAMES)
    }


# --- 7. ROOT ENDPOINT ---
@app.get("/")
def root():
    return {
        "message": "Phishing Detection API (Production Ready - Fixed Confidence)",
        "version": "2.1.0",
        "threshold": PHISHING_THRESHOLD,
        "endpoints": {
            "POST /predict": "Analyze a URL for phishing",
            "POST /debug": "Debug endpoint to see raw features",
            "GET /health": "Check API health"
        },
        "response_fields": {
            "is_phishing": "Boolean indicating if URL is phishing",
            "confidence": "Confidence in the final prediction (0-100%)",
            "raw_confidence": "Raw model confidence before threshold",
            "raw_prediction": "Model's raw prediction before threshold",
            "prediction_text": "Human readable result (PHISHING/LEGITIMATE)",
            "threshold_applied": "Confidence threshold used"
        }
    }


if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*60)
    print("🚀 Starting Phishing Detection API (Production Ready)")
    print("="*60)
    print(f"📊 Phishing Confidence Threshold: {PHISHING_THRESHOLD}%")
    print(f"🔧 Model Status: {'✅ Loaded' if model is not None else '❌ Not Loaded'}")
    print(f"📡 Server running at: http://0.0.0.0:8000")
    print(f"📖 API Docs: http://0.0.0.0:8000/docs")
    print("\n🔍 Test Commands:")
    print("   curl -X POST http://localhost:8000/predict -H 'Content-Type: application/json' -d '{\"url\": \"https://google.com\"}'")
    print("   curl -X POST http://localhost:8000/predict -H 'Content-Type: application/json' -d '{\"url\": \"https://mh.revayhystrix.com/iD\"}'")
    print("   curl http://localhost:8000/health")
    print("="*60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")