from sqlalchemy import Column, Integer, String, Text, DateTime, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"

    id           = Column(Integer, primary_key=True, index=True)
    alert_id     = Column(String, unique=True, index=True)   # CSK alert ID
    title        = Column(String, nullable=False)
    url          = Column(String, nullable=False)
    published_at = Column(String)
    severity     = Column(String)                            # AI extracted
    summary      = Column(Text)                              # AI enriched
    affected     = Column(Text)                              # Affected systems
    cves         = Column(Text)                              # Comma-separated CVEs
    threat_type  = Column(String)                            # AI extracted
    raw_content  = Column(Text)                              # Original page text
    stix_bundle  = Column(Text)                              # Full STIX JSON
    created_at   = Column(DateTime, default=datetime.utcnow)

DATABASE_URL = "sqlite:///./alerts.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()