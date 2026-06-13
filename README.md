<div align="center">

<br/>

```
 ██╗     ███████╗ ██████╗ ███╗   ██╗██╗██████╗  █████╗ ███████╗
 ██║     ██╔════╝██╔═══██╗████╗  ██║██║██╔══██╗██╔══██╗██╔════╝
 ██║     █████╗  ██║   ██║██╔██╗ ██║██║██║  ██║███████║███████╗
 ██║     ██╔══╝  ██║   ██║██║╚██╗██║██║██║  ██║██╔══██║╚════██║
 ███████╗███████╗╚██████╔╝██║ ╚████║██║██████╔╝██║  ██║███████║
 ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝
```

### *Defy the gravity of phishing attacks. Float above threats — effortlessly.*

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![XGBoost](https://img.shields.io/badge/XGBoost-ML%20Engine-EC6C30?style=for-the-badge&logo=xgboost&logoColor=white)](https://xgboost.readthedocs.io/)
[![Chrome Extension](https://img.shields.io/badge/Chrome%20Extension-MV3-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/)
[![Render](https://img.shields.io/badge/Deployed%20on-Render-46E3B7?style=for-the-badge&logo=render&logoColor=white)](https://render.com/)

</div>

---

## 🦅 What is Leonidas?

**Leonidas** is a real-time, AI-powered phishing URL detection system that operates directly inside your browser. Like the Spartan warrior it is named after, it stands at the gate — intercepting malicious URLs *before* they reach you.

The system combines a **27-feature extraction engine**, a trained **XGBoost classifier**, and a **Chrome Extension (Manifest V3)** to deliver instant link-safety verdicts on hover, without ever leaving the page.

> **Zero friction. Zero redirects. Zero compromise.**

---

## ✨ Key Features

- 🧠 **XGBoost ML Engine** — Trained on thousands of phishing & legitimate URLs; delivers probabilistic confidence scores
- 🌐 **27-Dimensional Feature Vector** — Lexical, host-based, redirect, content, and WHOIS features extracted per URL
- 🔗 **Redirect-Aware Analysis** — Follows all HTTP redirects to analyze the *true* final destination, not the visible link
- 🛡️ **DNS Gatekeeper** — Pre-flight `socket` DNS check hard-blocks dead or fake domains before any ML inference runs
- 🧩 **Chrome Extension (MV3)** — Hover-card UI injects into any webpage; analyze any link without clicking it
- ⚙️ **Configurable Confidence Threshold** — Adjustable phishing gate (default: 70%) prevents over-flagging ambiguous URLs
- 📡 **Production REST API** — FastAPI backend with `/predict`, `/debug`, and `/health` endpoints, deployed on Render
- 🔬 **Debug Endpoint** — Exposes raw feature values for full model interpretability and auditing
- 📦 **Containerization-Ready** — Clean dependency manifest and structured layout ready for Docker or cloud deployment

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| **ML Model** | XGBoost Classifier (`xgboost` + `scikit-learn`) |
| **API Backend** | FastAPI + Uvicorn |
| **Data Processing** | Pandas, NumPy, Joblib |
| **Web Scraping / Fetching** | Requests, BeautifulSoup4 |
| **Domain Intelligence** | `python-whois`, `socket` (DNS resolution) |
| **Browser Extension** | Chrome Extension Manifest V3, Vanilla JS + CSS |
| **Model Serialization** | Joblib (`.pkl` artifacts) |
| **Deployment** | Render (cloud PaaS), configurable for Docker |
| **Language** | Python 3.10+, JavaScript (ES2020) |

---

## 📦 Project Structure

```
Leonidas(V1.0)/
│
├── README.md                  # 📖 This file
├── xgbpredict.py              # 🖥️  CLI standalone predictor (local testing)
│
├── dataset_phishing.csv       # 📊 Raw phishing dataset (training source)
├── final_dataset.csv          # 📊 Cleaned/processed training dataset
├── final-Copy1.ipynb          # 🔬 Model training & evaluation notebook
│
├── backend/
│   ├── mytestingapp.py        # 🚀 Production FastAPI server (Render-ready)
│   ├── XGBmodel.pkl           # 🧠 Trained XGBoost classifier
│   ├── XGBscaler.pkl          # 📏 StandardScaler (fitted on training data)
│   ├── XGBencoder.pkl         # 🔤 LabelEncoder for has_https feature
│   └── requirements.txt       # 📋 Python dependencies
│
├── extension/
│   ├── manifest.json          # 📄 Chrome Extension Manifest V3
│   ├── content.js             # ⚡ Content script: hover detection + API calls
│   ├── styles.css             # 🎨 Popup card styles (neobrutalist design)
│   └── icons/                 # 🖼️  Extension icon assets (16, 32, 48, 128px)
│
└── Sample/
    └── *.png                  # 📸 Screenshots & demo images
```

---

## ⚙️ Installation & Setup

### Prerequisites

- Python **3.10+**
- `pip` package manager
- Google Chrome (for the browser extension)

---

### 1 · Clone the Repository

```bash
git clone https://github.com/TacticalHavoc/leonidas
```

### 2 · Create & Activate a Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate — Linux / macOS
source venv/bin/activate

# Activate — Windows
venv\Scripts\activate
```

### 3 · Install Dependencies

```bash
pip install -r backend/requirements.txt

# Also install python-whois (required for WHOIS lookups on Render):
pip install python-whois
```

### 4 · Verify Model Artifacts

Ensure the following `.pkl` files are present inside the `backend/` directory:

```
backend/XGBmodel.pkl
backend/XGBscaler.pkl
backend/XGBencoder.pkl
```

These are loaded automatically at server startup. If missing, the API starts in an **unhealthy** state and all predictions will fail with HTTP 503.

---

## 🚀 Usage Guide

### Option A — Run the FastAPI Server

```bash
# From the backend/ directory
cd backend
python mytestingapp.py
```

Or launch with Uvicorn directly:

```bash
uvicorn backend.mytestingapp:app --host 0.0.0.0 --port 8000 --reload
```

The API will be live at `http://localhost:8000`  
Interactive Swagger docs: `http://localhost:8000/docs`

---

### API Endpoints

#### `POST /predict` — Analyze a URL for Phishing

```bash
# Test a legitimate URL
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'

# Test a suspicious URL
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://mh.revayhystrix.com/iD"}'
```

**Sample Response (Phishing):**
```json
{
  "is_phishing": true,
  "confidence": 94.73,
  "raw_confidence": 94.73,
  "final_url": "http://mh.revayhystrix.com/iD",
  "prediction_text": "PHISHING",
  "threshold_applied": 70.0,
  "raw_prediction": "PHISHING"
}
```

**Sample Response (Legitimate):**
```json
{
  "is_phishing": false,
  "confidence": 98.21,
  "raw_confidence": 98.21,
  "final_url": "https://www.google.com/",
  "prediction_text": "LEGITIMATE",
  "threshold_applied": 70.0,
  "raw_prediction": "LEGITIMATE"
}
```

---

#### `POST /debug` — Inspect Raw Feature Values

```bash
curl -X POST http://localhost:8000/debug \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Sample Response:**
```json
{
  "url": "https://example.com",
  "final_url": "https://example.com/",
  "features": {
    "length_url": 19,
    "length_hostname": 11,
    "ip": 0,
    "nb_hyphens": 0,
    "nb_dots": 1,
    "domain_age": 10512,
    "has_https": true,
    "...": "..."
  },
  "feature_count": 27
}
```

#### `GET /health` — Check API Health

```bash
curl http://localhost:8000/health
```

---

### Option B — Run the CLI Predictor (No Server Needed)

For quick local testing without running a server:

```bash
# From the project root
python xgbpredict.py

# Prompt appears:
# Enter URL: https://suspicious-login-bankofamerica.com/verify
```

Outputs the XGBoost verdict, model confidence, and the **top 5 most influential features** based on `model.feature_importances_`.

---

### Option C — Install the Chrome Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer Mode** (toggle in the top-right corner)
3. Click **"Load unpacked"**
4. Select the `extension/` directory from this repository
5. The Leonidas extension is now active on all web pages

> **Switching to local backend:**  
> By default, `content.js` points to the Render-deployed API.  
> For local development, update line 66 in `extension/content.js`:
> ```js
> // Change this:
> const response = await fetch('https://RENDER URL/predict', {
> // To this:
> const response = await fetch('http://127.0.0.1:8000/predict', {
> ```
> Then ensure `python mytestingapp.py` is running on port 8000.

---

## 🧠 How It Works — Feature Engineering

Each URL is processed into a **27-dimensional feature vector** before being passed to XGBoost.  
Features span five distinct analytical layers:

| # | Feature | Category | Description |
|---|---|---|---|
| 1 | `length_url` | Lexical | Total character length of the fully-expanded URL |
| 2 | `length_hostname` | Lexical | Character count of the hostname / netloc component |
| 3 | `ip` | Host | `1` if the hostname resolves to a raw IP address (`\d+\.\d+`) |
| 4 | `nb_hyphens` | Lexical | Count of `-` in URL (hyphen-stuffing is a brand-spoofing tactic) |
| 5 | `nb_dots` | Lexical | Count of `.` in URL (excess dots = deep subdomain nesting) |
| 6 | `nb_at` | Lexical | Count of `@` (browser redirects to everything after `@`) |
| 7 | `nb_and` | Lexical | Count of `&` (query-string separator count) |
| 8 | `nb_underscore` | Lexical | Count of `_` (unusual in legitimate hostnames) |
| 9 | `nb_percent` | Lexical | Count of `%` (URL-encoded characters signal obfuscation) |
| 10 | `nb_slash` | Lexical | Count of `/` (deep path depth) |
| 11 | `nb_colon` | Lexical | Count of `:` (multiple colons can signal port manipulation) |
| 12 | `nb_comma` | Lexical | Count of `,` (commas are rare in legitimate URLs) |
| 13 | `port` | Host | Explicit non-standard port number in URL; `0` if default |
| 14 | `tld_in_path` | Lexical | `1` if TLD string appears in the URL path (e.g., `/paypal.com/login`) |
| 15 | `tld_in_subdomain` | Lexical | `1` if TLD appears in subdomain parts (e.g., `login.com.evil.xyz`) |
| 16 | `shortening_service` | Lexical | `1` if input URL uses `bit.ly`, `t.co`, `goo.gl`, or `tinyurl` |
| 17 | `path_extension` | Lexical | `1` if URL ends with `.php`, `.exe`, `.zip`, or `.rar` |
| 18 | `nb_redirection` | Network | Number of HTTP redirects followed (`len(response.history)`) |
| 19 | `nb_external_redirection` | Network | `1` if the final redirect crosses to a different domain |
| 20 | `login_form` | Content | `1` if any `<form>` tag is found in the page HTML |
| 21 | `iframe` | Content | `1` if any `<iframe>` tag is found in the page HTML |
| 22 | `domain_with_copyright` | Content | `1` if `'copyright'` string appears anywhere in the raw HTML |
| 23 | `whois_registered_domain` | WHOIS | `1` if domain returns a valid WHOIS record |
| 24 | `domain_registration_length` | WHOIS | Days remaining until domain expiration (short = suspicious) |
| 25 | `domain_age` | WHOIS | Days since domain creation date (new domain = higher risk) |
| 26 | `dns_record` | Host | Hardcoded `1` — DNS failure is caught upstream by the gatekeeper |
| 27 | `has_https` | Lexical | `1` if the final URL uses the HTTPS scheme (label-encoded) |

---

## 🏛️ Architecture Overview

```
[Chrome Extension]
  User hovers over <a> link
         │
         │  POST { url } via fetch()
         ▼
[FastAPI /predict endpoint]
         │
         ├─ Step 1: Input sanitization (strip, add scheme)
         ├─ Step 2: DNS check → socket.gethostbyname()
         │           └─ FAIL? Return { is_phishing: true, 100.0% }
         ├─ Step 3: expand_url() → follow all redirects → final_url
         ├─ Step 4: Parse URL into hostname / path / domain / TLD
         ├─ Step 5: Fetch HTML → count redirects → parse DOM (BS4)
         ├─ Step 6: WHOIS lookup → domain_age, reg_length, registered
         ├─ Step 7: Assemble 27-feature vector
         ├─ Step 8: LabelEncoder → StandardScaler → XGBClassifier
         ├─ Step 9: Apply confidence threshold (default: 70%)
         └─ Step 10: Return JSON verdict
         │
         ▼
[Chrome Extension]
  Render green ✅ or red ⚠️ result card on the page
```

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---


<div align="center">

*Built with precision. Deployed with purpose.*  
**Leonidas V1.0** — *Holding the line against phishing, one URL at a time.*

</div>
