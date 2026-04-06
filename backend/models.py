from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from database import Base
import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    threat_exposure_score = Column(Float, default=0.0)


class ScanHistory(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    
    scan_type = Column(String) # 'url' or 'email'
    target_domain = Column(String, index=True, nullable=True)
    target_ip = Column(String, nullable=True)
    content_hash = Column(String, index=True, nullable=True)
    
    content = Column(String)
    
    risk_score = Column(Float)
    initial_risk_score = Column(Float, nullable=True)
    is_phishing = Column(Boolean)
    explanation = Column(String)
    
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    last_rescanned_at = Column(DateTime, nullable=True)


class ThreatIntelligence(Base):
    __tablename__ = "threat_intel"

    domain = Column(String, primary_key=True, index=True)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    flag_count = Column(Integer, default=0)
    status = Column(String, default="suspicious")
