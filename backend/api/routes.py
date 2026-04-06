from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import database, models
import urllib.parse
from thefuzz import process
import joblib
import pandas as pd
import os
from ml.feature_extractor import extract_kaggle_features

model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml', 'phishing_model.pkl')
try:
    lr_model = joblib.load(model_path)
except Exception as e:
    print(f"Warning: Could not load ML model: {e}")
    lr_model = None

router = APIRouter()

class ScanURLRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    risk_score: float
    is_phishing: bool
    reasons: list[str]
    suggested_url: str | None = None

TRUSTED_DOMAINS = [
    "google.com", "amazon.com", "paypal.com", "apple.com", "microsoft.com", 
    "facebook.com", "netflix.com", "bankofamerica.com", "chase.com"
]

@router.post("/scan-url", response_model=ScanResponse)
def scan_url(request: ScanURLRequest, db: Session = Depends(database.get_db)):
    url = request.url.strip()
    if not url.startswith("http"):
        url = "http://" + url
        
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.split(":")[0].lower()
    
    risk_score = 0.0
    reasons = []
    suggested_url = None
    
    # 1. Similarity Engine (Fuzzy Matching)
    # Exclude exact matches first:
    if domain in TRUSTED_DOMAINS:
        # It's exactly a trusted domain
        pass
    else:
        # Check fuzzy matching
        closest_match, score = process.extractOne(domain, TRUSTED_DOMAINS)
        if score > 85 and score < 100:
            risk_score += 80  # Typo squatting is extremely high risk
            reasons.append(f"Domain '{domain}' is suspiciously similar to trusted domain '{closest_match}'.")
            suggested_url = f"https://{closest_match}"
    
    # 2. Rule based Engine
    if not url.startswith("https://"):
        risk_score += 30
        reasons.append("Connection is not secured with HTTPS.")
        
    suspicious_chars = ['@', '|', '%']
    found_chars = [c for c in suspicious_chars if c in url]
    if found_chars:
        risk_score += 20
        reasons.append(f"Suspicious characters detected in URL: {' '.join(found_chars)}")
        
    if len(url) > 100:
        risk_score += 15
        reasons.append("URL length is unusually long, hiding real intent.")
        
    import re
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        risk_score += 50
        reasons.append("Domain is a raw IP address, typically used in evasion.")
        
    if domain.count('.') > 2:
        risk_score += 10
        reasons.append(f"Multiple subdomains detected ({domain.count('.')} sublevels).")

    # 3. ML Layer (Logistic Regression)
    if lr_model is not None:
        features = extract_kaggle_features(url)
        feature_columns = [
            'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
            'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
            'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
            'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
            'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath'
        ]
        inference_features = {k: features[k] for k in feature_columns}
        df_features = pd.DataFrame([inference_features], columns=feature_columns)
        
        try:
            prob = lr_model.predict_proba(df_features)[0][1] * 100
            ml_risk = prob
            risk_score = (risk_score * 0.6) + (ml_risk * 0.4)
            reasons.append(f"ML Model Analysis computed a baseline risk of {ml_risk:.1f}%.")
        except Exception:
            pass

    risk_score = min(risk_score, 100.0)
    is_phishing = risk_score > 60.0
    
    if not reasons:
        reasons.append("No suspicious indicators found. URL appears safe.")
        
    # Save to history
    new_scan = models.ScanHistory(
        user_id=1, 
        url=url,
        domain_name=domain,
        risk_score=risk_score,
        is_phishing=is_phishing,
        explanation="; ".join(reasons),
        suggested_url=suggested_url
    )
    db.add(new_scan)
    db.commit()

    return ScanResponse(
        risk_score=risk_score, 
        is_phishing=is_phishing, 
        reasons=reasons, 
        suggested_url=suggested_url
    )

class LoginRequest(BaseModel):
    email: str
    password: str

@router.post("/auth/login")
def login(request: LoginRequest):
    if not request.email.lower().endswith("@gmail.com"):
        raise HTTPException(status_code=400, detail="Only @gmail.com accounts are permitted.")
    if len(request.password) < 6:
        raise HTTPException(status_code=400, detail="Password too short.")
    
    return {"token": "dummy_phishshield_token_123"}

# optimize 25423 route handling

# optimize 99431 route handling

# optimize 80787 route handling

# optimize 28382 route handling

# optimize 94948 route handling

# optimize 57527 route handling

# optimize 2782 route handling

# optimize 97205 route handling

# optimize 62085 route handling

# optimize 43220 route handling

# optimize 86123 route handling

# optimize 60046 route handling
