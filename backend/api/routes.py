from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
import database, models
import urllib.parse
from thefuzz import process
import joblib
import pandas as pd
import os
import re
import io
import subprocess
import sys
from ml.preprocess import preprocess_single_url, FEATURE_COLUMNS

# ── Model loading ──────────────────────────────────────────────────────────────
model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml', 'phishing_model.pkl')

def load_model():
    try:
        return joblib.load(model_path)
    except Exception as e:
        print(f"Warning: Could not load ML model: {e}")
        return None

lr_model = load_model()

# ── Router & schemas ───────────────────────────────────────────────────────────
router = APIRouter()

class ScanURLRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    risk_score: float
    is_phishing: bool
    reasons: list[str]
    suggested_url: str | None = None
    feature_breakdown: dict | None = None

class LoginRequest(BaseModel):
    email: str
    password: str

class TrainResponse(BaseModel):
    success: bool
    message: str
    accuracy: float | None = None

# ── Trusted domain list for fuzzy matching ─────────────────────────────────────
TRUSTED_DOMAINS = [
    "google.com", "amazon.com", "paypal.com", "apple.com", "microsoft.com",
    "facebook.com", "netflix.com", "bankofamerica.com", "chase.com",
    "instagram.com", "twitter.com", "linkedin.com", "github.com",
    "yahoo.com", "gmail.com", "outlook.com", "dropbox.com",
]

# ── /scan-url ──────────────────────────────────────────────────────────────────
@router.post("/scan-url", response_model=ScanResponse)
def scan_url(request: ScanURLRequest, db: Session = Depends(database.get_db)):
    global lr_model
    url = request.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.split(":")[0].lower()

    risk_score = 0.0
    reasons = []
    suggested_url = None

    # 1. Fuzzy similarity engine (typo-squatting detection)
    if domain and domain not in TRUSTED_DOMAINS:
        match_result = process.extractOne(domain, TRUSTED_DOMAINS)
        if match_result:
            closest_match, score = match_result
            if 85 < score < 100:
                risk_score += 80
                reasons.append(
                    f"Domain '{domain}' looks like typo-squatting of '{closest_match}' "
                    f"(similarity {score}%)."
                )
                suggested_url = f"https://{closest_match}"

    # 2. Rule-based engine
    if not url.startswith("https://"):
        risk_score += 30
        reasons.append("Connection is not secured with HTTPS.")

    found_chars = [c for c in ['@', '|'] if c in url]
    if found_chars:
        risk_score += 20
        reasons.append(f"Suspicious characters in URL: {' '.join(found_chars)}")

    if len(url) > 100:
        risk_score += 15
        reasons.append(f"URL is unusually long ({len(url)} chars) — often used to hide real destination.")

    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        risk_score += 50
        reasons.append("Domain is a raw IP address — legitimate sites don't use IPs.")

    if domain.count('.') > 3:
        risk_score += 15
        reasons.append(f"Excessive subdomain depth ({domain.count('.')} dots) is a red flag.")

    # 3. ML layer (Logistic Regression on Kaggle features)
    features = preprocess_single_url(url)
    feature_breakdown = {}
    if lr_model is None:
        lr_model = load_model()

    if lr_model is not None:
        try:
            df_feat = pd.DataFrame([{k: features[k] for k in FEATURE_COLUMNS}], columns=FEATURE_COLUMNS)
            prob = lr_model.predict_proba(df_feat)[0][1] * 100
            risk_score = (risk_score * 0.6) + (prob * 0.4)
            reasons.append(f"ML model (Logistic Regression) assigned {prob:.1f}% baseline phishing probability.")
            # Human-readable feature breakdown
            feature_breakdown = {
                "URL Length": features['UrlLength'],
                "Subdomain Depth": features['SubdomainLevel'],
                "Has IP Address": bool(features['IpAddress']),
                "No HTTPS": bool(features['NoHttps']),
                "@ Symbol": bool(features['AtSymbol']),
                "High Entropy (random string)": bool(features['RandomString']),
                "Double Slash in Path": bool(features['DoubleSlashInPath']),
            }
        except Exception as ex:
            print(f"ML inference error: {ex}")

    risk_score = min(risk_score, 100.0)
    is_phishing = risk_score > 55.0

    if not reasons:
        reasons.append("No suspicious indicators found. URL appears safe.")

    # Save to scan history
    try:
        new_scan = models.ScanHistory(
            user_id=1,
            url=url,
            domain_name=domain,
            risk_score=risk_score,
            is_phishing=is_phishing,
            explanation="; ".join(reasons),
            suggested_url=suggested_url,
        )
        db.add(new_scan)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"DB save error: {e}")

    return ScanResponse(
        risk_score=risk_score,
        is_phishing=is_phishing,
        reasons=reasons,
        suggested_url=suggested_url,
        feature_breakdown=feature_breakdown,
    )

# ── /auth/login ────────────────────────────────────────────────────────────────
@router.post("/auth/login")
def login(request: LoginRequest):
    if not request.email.lower().endswith("@gmail.com"):
        raise HTTPException(status_code=400, detail="Only @gmail.com accounts are permitted.")
    if len(request.password) < 6:
        raise HTTPException(status_code=400, detail="Password is too short (min 6 chars).")
    return {"token": "phishshield_demo_token_2026", "email": request.email}

# ── /train ─────────────────────────────────────────────────────────────────────
@router.post("/train", response_model=TrainResponse)
async def train_model(file: UploadFile = File(None)):
    """
    Re-train the Logistic Regression model.
    If a CSV file is uploaded it is used; otherwise the built-in dataset.csv is used.
    Returns training accuracy after completion.
    """
    global lr_model

    backend_dir = os.path.dirname(os.path.dirname(__file__))

    # If a new CSV was uploaded, save it as dataset.csv
    if file and file.filename:
        content = await file.read()
        try:
            df_uploaded = pd.read_csv(io.BytesIO(content))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not parse CSV: {e}")

        # Save over dataset.csv
        upload_path = os.path.join(backend_dir, 'dataset.csv')
        df_uploaded.to_csv(upload_path, index=False)

    # Run the train script in a subprocess so uvicorn doesn't block
    script = os.path.join(backend_dir, 'ml', 'train_model.py')
    result = subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True,
        cwd=backend_dir,
    )

    if result.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail=f"Training failed:\n{result.stderr}"
        )

    # Reload the freshly trained model
    lr_model = load_model()

    # Parse accuracy from stdout  e.g. "accuracy    0.92"
    accuracy = None
    for line in result.stdout.splitlines():
        if 'accuracy' in line.lower():
            parts = line.split()
            for part in parts:
                try:
                    v = float(part)
                    if 0 < v <= 1:
                        accuracy = round(v * 100, 2)
                        break
                except ValueError:
                    pass

    return TrainResponse(
        success=True,
        message="Model retrained successfully on the latest dataset.",
        accuracy=accuracy,
    )

# ── /scan-history ──────────────────────────────────────────────────────────────
@router.get("/scan-history")
def get_scan_history(db: Session = Depends(database.get_db)):
    scans = db.query(models.ScanHistory).order_by(
        models.ScanHistory.id.desc()
    ).limit(50).all()
    return [
        {
            "id": s.id,
            "url": s.url,
            "domain_name": s.domain_name,
            "risk_score": s.risk_score,
            "is_phishing": s.is_phishing,
            "explanation": s.explanation,
            "suggested_url": s.suggested_url,
        }
        for s in scans
    ]
