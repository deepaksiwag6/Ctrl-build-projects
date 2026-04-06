import asyncio
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from database import SessionLocal
import models
import urllib.parse
import random

def extract_domain(url: str) -> str:
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed_uri = urllib.parse.urlparse(url)
        return parsed_uri.netloc.split(':')[0]
    except Exception:
        return ""

def smart_rescan_job():
    """Background task to simulate re-evaluating historical items."""
    print(f"[{datetime.utcnow()}] Running Smart Re-Scan Job...")
    
    db = SessionLocal()
    try:
        # Find scans from the last 7 days that weren't definitely safe or definitely malicious
        cutoff_date = datetime.utcnow() - timedelta(days=7)
        recent_suspicious = db.query(models.ScanHistory).filter(
            models.ScanHistory.timestamp >= cutoff_date,
            models.ScanHistory.risk_score >= 20,
            models.ScanHistory.risk_score < 70
        ).all()

        for scan in recent_suspicious:
            domain = extract_domain(scan.content) if scan.scan_type == 'url' else None
            
            # Simulated updated threat intelligence
            # E.g. what if a domain suddenly got flagged globally
            if domain:
                intel = db.query(models.ThreatIntelligence).filter_by(domain=domain).first()
                if not intel:
                    intel = models.ThreatIntelligence(domain=domain)
                    db.add(intel)
                
                # Simulate a spike in global reports randomly for the demo
                if random.random() > 0.8:
                    intel.flag_count += random.randint(1, 10)
                    if intel.flag_count > 5:
                        intel.status = "malicious"
                        # Retroactively penalize the historical scan
                        scan.risk_score = 95.0
                        scan.is_phishing = True
                        scan.explanation += " [LATE UPDATE: Domain has now been globally flagged as highly malicious]."
                        
                        # Increment user exposure
                        user = db.query(models.User).filter_by(id=scan.user_id).first()
                        if user:
                            user.threat_exposure_score += 15.0

            scan.last_rescanned_at = datetime.utcnow()
            
        db.commit()
        print(f"[{datetime.utcnow()}] Processed {len(recent_suspicious)} historical items.")
    finally:
        db.close()
