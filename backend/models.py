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
    
    url = Column(String, index=True)
    domain_name = Column(String, index=True, nullable=True)
    
    risk_score = Column(Float)
    is_phishing = Column(Boolean)
    explanation = Column(String)
    suggested_url = Column(String, nullable=True)
    
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)


class ThreatIntelligence(Base):
    __tablename__ = "threat_intel"

    domain = Column(String, primary_key=True, index=True)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    flag_count = Column(Integer, default=0)
    status = Column(String, default="suspicious")

# model constraint 61519

# model constraint 89131

# model constraint 40147

# model constraint 24866

# model constraint 25107
