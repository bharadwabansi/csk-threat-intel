from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import json
import time
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor(max_workers=1)

from database import init_db, get_db, Alert
from scraper import fetch_alert_list, fetch_alert_detail
from enricher import enrich_alert
from stix_converter import generate_stix_bundle

load_dotenv()

MAX_ALERTS_PER_CRAWL = 10   # max alerts to process per crawl
DELAY_BETWEEN_CALLS  = 5    # seconds to wait between calls

app = FastAPI(title="CSK Threat Intelligence Portal", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()
    print("[main] Database initialized")


# ENDPOINTS

@app.get("/")
def root():
    return {"message": "CSK Threat Intelligence Portal is running!"}


@app.post("/api/crawl")
def crawl_alerts(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    executor.submit(run_crawl_pipeline, db)
    return {"message": f"Crawl started! Processing up to {MAX_ALERTS_PER_CRAWL} new alerts."}

def run_crawl_pipeline(db: Session):
    print("[pipeline] Starting crawl pipeline...")
    alerts    = fetch_alert_list()
    new_count = 0

    for alert_meta in alerts:

        # Stop after limit
        if new_count >= MAX_ALERTS_PER_CRAWL:
            print(f"[pipeline] Reached limit of {MAX_ALERTS_PER_CRAWL} alerts. Stopping.")
            break

        alert_id = alert_meta["alert_id"]

        # Skip if already in DB
        existing = db.query(Alert).filter(Alert.alert_id == alert_id).first()
        if existing:
            print(f"[pipeline] Skipping existing alert: {alert_id}")
            continue

        # Fetch detail page
        raw_content = fetch_alert_detail(alert_meta["url"])
        if not raw_content:
            continue

        print(f"[pipeline] Calling Groq for: {alert_id}")

        # AI enrichment
        enriched = enrich_alert(raw_content)

        # Wait before next Gemini call to avoid quota exhaustion
        print(f"[pipeline] Waiting {DELAY_BETWEEN_CALLS}s before next call...")
        time.sleep(DELAY_BETWEEN_CALLS)

        # STIX conversion
        try:
            stix_bundle = generate_stix_bundle(alert_meta, enriched)
        except Exception as e:
            print(f"[pipeline] STIX error for {alert_id}: {e}")
            stix_bundle = "{}"

        # Save to DB
        db_alert = Alert(
            alert_id     = alert_id,
            title        = alert_meta["title"],
            url          = alert_meta["url"],
            published_at = alert_meta.get("published_at", ""),
            severity     = enriched.get("severity", "Unknown"),
            summary      = enriched.get("summary", ""),
            affected     = ", ".join(enriched.get("affected_systems", [])),
            cves         = ", ".join(enriched.get("cves", [])),
            threat_type  = enriched.get("threat_type", "Unknown"),
            raw_content  = raw_content[:5000],
            stix_bundle  = stix_bundle,
        )
        db.add(db_alert)
        db.commit()
        new_count += 1
        print(f"[pipeline] Saved alert {new_count}/{MAX_ALERTS_PER_CRAWL}: {alert_id}")

    print(f"[pipeline] Done. {new_count} new alerts saved.")


@app.get("/api/alerts")
def get_alerts(
    skip: int = 0,
    limit: int = 20,
    search: str = "",
    severity: str = "",
    db: Session = Depends(get_db)
):
    query = db.query(Alert)

    if search:
        query = query.filter(
            Alert.title.contains(search)       |
            Alert.summary.contains(search)     |
            Alert.cves.contains(search)        |
            Alert.threat_type.contains(search)
        )

    if severity:
        query = query.filter(Alert.severity == severity)

    total  = query.count()
    alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()

    return {
        "total":  total,
        "alerts": [_format_alert(a) for a in alerts]
    }


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _format_alert(alert, include_stix=True)


@app.get("/api/alerts/{alert_id}/stix")
def get_stix(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    try:
        return json.loads(alert.stix_bundle)
    except Exception:
        return {"error": "Invalid STIX data"}


@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total    = db.query(Alert).count()
    critical = db.query(Alert).filter(Alert.severity == "Critical").count()
    high     = db.query(Alert).filter(Alert.severity == "High").count()
    medium   = db.query(Alert).filter(Alert.severity == "Medium").count()
    low      = db.query(Alert).filter(Alert.severity == "Low").count()

    return {
        "total":    total,
        "critical": critical,
        "high":     high,
        "medium":   medium,
        "low":      low,
    }


# HELPER


def _format_alert(alert: Alert, include_stix: bool = False) -> dict:
    data = {
        "id":           alert.id,
        "alert_id":     alert.alert_id,
        "title":        alert.title,
        "url":          alert.url,
        "published_at": alert.published_at,
        "severity":     alert.severity,
        "summary":      alert.summary,
        "affected":     alert.affected,
        "cves":         alert.cves,
        "threat_type":  alert.threat_type,
        "created_at":   str(alert.created_at),
    }
    if include_stix:
        try:
            data["stix_bundle"] = json.loads(alert.stix_bundle)
        except Exception:
            data["stix_bundle"] = {}
    return data


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
