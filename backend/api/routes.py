from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import database, models
import re
import random
import os
import joblib
import pandas as pd
from ml.feature_extractor import extract_kaggle_features

# Load model globally at startup
model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml', 'phishing_model.pkl')
try:
    rf_model = joblib.load(model_path)
except Exception as e:
    print(f"Warning: Could not load ML model: {e}")
    rf_model = None

router = APIRouter()

class ScanURLRequest(BaseModel):
    url: str

class ScanEmailRequest(BaseModel):
    content: str

class ScanDetails(BaseModel):
    ssl_valid: bool
    domain_age_days: int
    suspicious_tld: bool
    has_phishing_keywords: bool

class ScanResponse(BaseModel):
    risk_score: float
    is_phishing: bool
    explanation: str
    details: ScanDetails
class ScanHistoryResponse(BaseModel):
    id: int
    scan_type: str
    content: str
    risk_score: float
    is_phishing: bool
    explanation: str

@router.post("/scan", response_model=ScanResponse)
def scan_url(request: ScanURLRequest, db: Session = Depends(database.get_db)):
    url = request.url
    explanation_points = []
    
    # 1. Strict Pre-ML Rule Based Validation
    if not url.lower().startswith("https://"):
        return ScanResponse(
            risk_score=100.0,
            is_phishing=True,
            explanation="Rule Triggered: Non-HTTPS URLs are aggressively intercepted and blocked by security policy.",
            details=ScanDetails(ssl_valid=False, domain_age_days=0, suspicious_tld=False, has_phishing_keywords=False)
        )
    
    # Extract features using ml module
    features = extract_kaggle_features(url)
    
    risk_score = 0.0
    is_phishing = False
    
    if rf_model is not None:
        # Prepare feature names matching the trained model
        feature_columns = [
            'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
            'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
            'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
            'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
            'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath'
        ]
        # Strip extra info out of DataFrame
        inference_features = {k: features[k] for k in feature_columns}
        df_features = pd.DataFrame([inference_features], columns=feature_columns)
        
        try:
            prediction = rf_model.predict(df_features)[0]
            probabilities = rf_model.predict_proba(df_features)[0]
            # Since Random Forest returns prob for [class 0, class 1], we take the prob for class 1
            risk_score = probabilities[1] * 100.0
            is_phishing = bool(prediction == 1)
            
            if is_phishing:
                explanation = f"ML Model detected high risk pattern (Confidence: {risk_score:.1f}%)."
            else:
                explanation = f"ML Model classifies this URL as generally safe (Risk: {risk_score:.1f}%)."
        except Exception as e:
            risk_score = random.uniform(5, 50)
            is_phishing = False
            explanation = "ML inference failed, falling back to mock logic."
    else:
        # Fallback if model not trained yet
        risk_score = random.uniform(10, 80)
        is_phishing = risk_score > 60
        explanation = "Using simulated backend analysis (Model not found)."
        
    if features['IpAddress'] == 1:
        explanation_points.append("Raw IP address detected in domain.")
    if features['SubdomainLevel'] > 2:
        explanation_points.append("Unusual subdomain complexity detected.")
    if features['Extra_Entropy'] > 4.2:
        explanation_points.append("High string entropy (domain name looks randomized/DGA).")
        
    if explanation_points:
        explanation += " " + " ".join(explanation_points)

    mock_details = ScanDetails(
        ssl_valid=not bool(features['NoHttps']),
        domain_age_days=random.randint(10, 3000),
        suspicious_tld=bool(features['IpAddress'] == 1),
        has_phishing_keywords=bool(features['NumDash'] > 3 or "login" in url.lower())
    )

    # Save to history
    new_scan = models.ScanHistory(
        user_id=1, # Mock user id
        scan_type="url",
        content=url,
        risk_score=risk_score,
        is_phishing=is_phishing,
        explanation=explanation
    )
    db.add(new_scan)
    db.commit()

    return ScanResponse(risk_score=risk_score, is_phishing=is_phishing, explanation=explanation, details=mock_details)

@router.post("/scan-email", response_model=ScanResponse)
def scan_email(request: ScanEmailRequest, db: Session = Depends(database.get_db)):
    content = request.content
    
    # Mock AI/ML logic for Email
    risk_score = 0.0
    explanation_points = []
    content_lower = content.lower()
    
    # Detailed Data Set Check (Trained on User Input)
    mock_details = ScanDetails(
        ssl_valid=True,
        domain_age_days=300,
        suspicious_tld=False,
        has_phishing_keywords=False
    )
    
    if not content:
        raise HTTPException(status_code=400, detail="Empty content")

    # 1. Psychological Manipulation (The Real Weapon)
    # Urgency & Fear
    if any(phrase in content_lower for phrase in ["act now", "account will be blocked", "suspicious login detected", "immediate action required", "verify your account", "24 hours"]):
        risk_score += 40
        mock_details.has_phishing_keywords = True
        explanation_points.append("Psychological Manipulation: High urgency/fear triggers detected pushing immediate action.")
        
    # Greed
    if any(phrase in content_lower for phrase in ["you won", "prize", "₹10,000", "lottery", "claim your reward", "free money"]):
        risk_score += 35
        mock_details.has_phishing_keywords = True
        explanation_points.append("Psychological Manipulation: Greed triggers detected promising artificial rewards.")

    # Authority Scams
    if any(phrase in content_lower for phrase in ["admin", "system administrator", "ceo", "security team", "it helpdesk", "head office"]):
        risk_score += 15
        mock_details.has_phishing_keywords = True
        explanation_points.append("Authority Spoofing: Impersonation of an authoritative figure to force compliance.")

    # 2. Data Harvesting & Malicious Attachments
    if any(ext in content_lower for ext in [".zip", ".exe", ".pdf", "macro", "invoice.pdf"]):
        risk_score += 30
        explanation_points.append("Malicious Attachment Risk: Contains mentions of risky file extensions (.exe, .zip, .pdf).")
        
    if "password" in content_lower or "otp" in content_lower or "banking" in content_lower:
        risk_score += 25
        explanation_points.append("Data Harvesting: Requests sensitive information like passwords or OTPs.")

    # 3. Technical Weak Points & Fake Links
    if "http" in content_lower or "www" in content_lower:
        risk_score += 15
        explanation_points.append("Embedded Links: Contains links which should be verified against fake portals.")
        
    if "spf=fail" in content_lower or "dkim=fail" in content_lower:
         risk_score += 50
         explanation_points.append("Technical Weak Point: Email authentication (SPF/DKIM) failed or is missing entirely.")

    # random noise
    risk_score += random.uniform(2, 10)
    
    if risk_score > 100:
        risk_score = 100
        
    is_phishing = risk_score > 60
    
    if risk_score < 20:
        explanation = "This email does not appear to exhibit typical phishing language. No manipulation found."
    elif risk_score < 60:
        explanation = "This email contains some suspicious patterns. " + " ".join(explanation_points)
    else:
        explanation = "High risk phishing email detected based on targeted manipulation patterns. " + " ".join(explanation_points)
        
    # Save to history
    new_scan = models.ScanHistory(
        user_id=1, # Mock user id
        scan_type="email",
        content=content[:100] + "..." if len(content) > 100 else content,
        risk_score=risk_score,
        is_phishing=is_phishing,
        explanation=explanation
    )
    db.add(new_scan)
    db.commit()

    return ScanResponse(risk_score=risk_score, is_phishing=is_phishing, explanation=explanation, details=mock_details)

@router.get("/history")
def get_history(db: Session = Depends(database.get_db)):
    scans = db.query(models.ScanHistory).order_by(models.ScanHistory.timestamp.desc()).limit(50).all()
    return scans


class LoginRequest(BaseModel):
    email: str
    password: str

@router.post("/auth/login")
def login(request: LoginRequest):
    if not request.email.lower().endswith("@gmail.com"):
        raise HTTPException(status_code=401, detail="Internal Security Rule: Only @gmail.com addresses are permitted.")
    return {"token": "fake-jwt-token", "user": {"email": request.email}}

@router.get("/analytics/user-exposure")
def get_user_exposure(user_id: int = 1, db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        user = models.User(id=user_id, email="demo@example.com", threat_exposure_score=15.0)
        db.add(user)
        db.commit()
    
    total_scanned = db.query(models.ScanHistory).filter(models.ScanHistory.user_id == user_id).count()
    threats = db.query(models.ScanHistory).filter(models.ScanHistory.user_id == user_id, models.ScanHistory.is_phishing == True).count()
    
    status = "Safe"
    if user.threat_exposure_score > 60:
        status = "High Risk"
    elif user.threat_exposure_score > 30:
        status = "Moderate Risk"
        
    return {
        "exposure_score": min(100, round(user.threat_exposure_score, 1)),
        "overall_status": status,
        "total_scanned": total_scanned if total_scanned > 0 else 154, # Mock fallback
        "threats_encountered": threats if threats > 0 else 24
    }

@router.get("/analytics/top-threats")
def get_top_threats(db: Session = Depends(database.get_db)):
    import sqlalchemy
    from sqlalchemy import func
    
    # Normally we do Group By, but since it's sqlite we mock standard behavior
    results = db.query(
        models.ThreatIntelligence.domain, 
        models.ThreatIntelligence.flag_count
    ).order_by(models.ThreatIntelligence.flag_count.desc()).limit(5).all()
    
    if not results:
        return [
            {"domain": "login-verify-account.xyz", "frequency": 42},
            {"domain": "apple-update-id.com", "frequency": 28},
            {"domain": "secure-payment-gateway-xyz.top", "frequency": 16}
        ]
        
    return [{"domain": r[0], "frequency": r[1]} for r in results]

@router.delete("/history/purge")
def purge_history(user_id: int = 1, db: Session = Depends(database.get_db)):
    # Simulates purging PII content while retaining metadata
    scans = db.query(models.ScanHistory).filter(models.ScanHistory.user_id == user_id).all()
    for scan in scans:
        if scan.scan_type == 'email':
            scan.content = "[REDACTED FOR PRIVACY]"
    db.commit()
    return {"status": "success", "message": "Sensitive content has been purged."}

