import re
import warnings
from urllib.parse import urlparse

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

warnings.filterwarnings("ignore", category=UserWarning)

app = FastAPI()

# Allows your Chrome Extension to communicate with this script safely
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
model = joblib.load("XGBmodel.pkl")
scaler = joblib.load("XGBscaler.pkl")
encoder = joblib.load("XGBencoder.pkl")


class URLInput(BaseModel):
    url: str


def extract_features(input_url):
    # This is a simplified fallback feature extractor to keep things lightning fast in the cloud
    try:
        parsed = urlparse(input_url)
        hostname = parsed.netloc
        path = parsed.path
        tld = hostname.split(".")[-1] if "." in hostname else ""

        features = [
            len(input_url),
            len(hostname),
            1 if re.match(r"\d+\.\d+", hostname) else 0,
            input_url.count("-"),
            input_url.count("."),
            input_url.count("@"),
            input_url.count("&"),
            input_url.count("_"),
            input_url.count("%"),
            input_url.count("/"),
            input_url.count(":"),
            input_url.count(","),
            parsed.port if parsed.port else 0,
            1 if tld in path else 0,
            1 if tld in hostname.split(".")[:-2] else 0,
            1
            if any(
                s in input_url.lower() for s in ["bit.ly", "t.co", "goo.gl", "tinyurl"]
            )
            else 0,
            1
            if any(input_url.lower().endswith(e) for e in ["php", "exe", "zip", "rar"])
            else 0,
            0,
            0,  # Redirections set to baseline default
            0,
            0,
            0,  # Page scraping set to baseline default
            1,
            365,
            365,  # WHOIS defaults to prevent cloud crashes
            1,
            1 if input_url.lower().startswith("https") else 0,
        ]
        return features
    except:
        return [0] * 27


@app.post("/predict")
def predict(data: URLInput):
    url = data.url.strip()
    if not url.startswith("http"):
        url = "http://" + url

    # 1. Extract Features
    raw_features = extract_features(url)

    try:
        # 2. Transform input features using your trained encoder and scaler
        raw_features[26] = encoder.transform([raw_features[26]])[0]
        df = pd.DataFrame([raw_features], columns=FEATURE_NAMES)
        scaled_df = scaler.transform(df)

        # 3. Model Predict
        prediction = int(model.predict(scaled_df)[0])
        probabilities = model.predict_proba(scaled_df)[0]
        confidence = float(probabilities[prediction] * 100)

        return {"is_phishing": prediction == 1, "confidence": confidence}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
