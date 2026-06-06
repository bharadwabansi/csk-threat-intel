import requests
from bs4 import BeautifulSoup
import re
import time
import subprocess
import sys
import json
from typing import Optional

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

BASE_URL  = "https://www.csk.gov.in"
ALERT_URL = "https://www.csk.gov.in/alerts.html"


def fetch_alert_list() -> list[dict]:
    try:
        resp = requests.get(ALERT_URL, headers=HEADERS, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        print(f"[scraper] Failed to fetch alert list: {e}")
        return []

    soup   = BeautifulSoup(resp.text, "lxml")
    alerts = []
    seen   = set()

    for a in soup.find_all("a", href=True):
        href  = a["href"].strip()
        title = a.get_text(strip=True)

        # Only pick links under /alerts/ subfolder — these are real alert pages
        if not re.search(r"/alerts/[^/]+\.html$", href):
            continue

        if not title or len(title) < 3:
            continue

        # Build full URL
        if href.startswith("http"):
            full_url = href
        else:
            full_url = BASE_URL + ("" if href.startswith("/") else "/") + href

        if full_url in seen:
            continue
        seen.add(full_url)

        # Slug from filename
        slug = href.rstrip("/").split("/")[-1].replace(".html", "")

        alerts.append({
            "alert_id":     slug,
            "title":        title,
            "url":          full_url,
            "published_at": "",
        })

    print(f"[scraper] Found {len(alerts)} alerts on listing page")
    return alerts


def fetch_alert_detail(url: str) -> Optional[str]:
    try:
        # Run playwright in a completely separate process
        # This avoids ALL async event loop conflicts with FastAPI
        script = f"""
import asyncio
from playwright.async_api import async_playwright
import json

async def fetch():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto("{url}", timeout=15000)
        await page.wait_for_load_state("networkidle")
        await page.evaluate(
            "document.querySelectorAll('script,style,nav,header,footer,aside').forEach(el=>el.remove())"
        )
        text = await page.inner_text("body")
        await browser.close()
        print(text)

asyncio.run(fetch())
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30
        )

        text  = result.stdout
        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and len(ln.strip()) > 3]
        clean = "\n".join(lines)

        print(f"[scraper] Got {len(clean)} chars from {url}")
        return clean if clean else None

    except Exception as e:
        print(f"[scraper] Failed to fetch {url}: {e}")
        return None

if __name__ == "__main__":
    alerts = fetch_alert_list()
    print(f"\nTotal alerts found: {len(alerts)}")
    for a in alerts[:5]:
        print(f"  - {a['title'][:60]} | {a['url']}")
    if alerts:
        print("\nFetching detail for first alert...")
        detail = fetch_alert_detail(alerts[0]["url"])
        print("Detail snippet:", detail[:500] if detail else "None")