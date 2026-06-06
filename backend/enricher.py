import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))


PROMPT_TEMPLATE = """
You are a cybersecurity analyst. Analyze the following security alert and extract structured information.

ALERT CONTENT:
{alert_text}

Return ONLY a valid JSON object with exactly these fields:
{{
  "severity": "Critical | High | Medium | Low | Unknown",
  "threat_type": "e.g. Vulnerability, Malware, Phishing, Ransomware, DDoS, Data Breach, etc.",
  "summary": "2-3 sentence plain English summary of the alert",
  "affected_systems": ["list", "of", "affected", "software", "or", "systems"],
  "cves": ["CVE-XXXX-XXXXX", "..."],
  "iocs": {{
    "ips": [],
    "domains": [],
    "hashes": [],
    "urls": []
  }},
  "attack_patterns": ["list of attack techniques mentioned"],
  "recommendations": "Brief mitigation advice"
}}

Rules:
- Return ONLY the JSON, no markdown, no explanation
- If a field has no data, use empty list [] or "Unknown"
- CVEs must follow format CVE-YYYY-NNNNN
"""


def enrich_alert(alert_text: str) -> dict:
    """
    Send alert text to Groq and return enriched structured data.
    """
    if not alert_text or len(alert_text.strip()) < 50:
        return _empty_enrichment()

    try:
        prompt   = PROMPT_TEMPLATE.format(alert_text=alert_text[:4000])  # cap to avoid token limits
        # Add this
        response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000,
        )
        raw = response.choices[0].message.content.strip()

        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        data = json.loads(raw)
        print(f"[enricher] Enrichment successful — severity: {data.get('severity')}, threat: {data.get('threat_type')}")
        return data

    except json.JSONDecodeError as e:
        print(f"[enricher] JSON parse error: {e}")
        return _empty_enrichment()
    except Exception as e:
        print(f"[enricher] Groq API error: {e}")
        return _empty_enrichment()


def _empty_enrichment() -> dict:
    return {
        "severity":         "Unknown",
        "threat_type":      "Unknown",
        "summary":          "",
        "affected_systems": [],
        "cves":             [],
        "iocs":             {"ips": [], "domains": [], "hashes": [], "urls": []},
        "attack_patterns":  [],
        "recommendations":  ""
    }


if __name__ == "__main__":
    # Quick test
    sample = """
    A critical vulnerability has been discovered in Apache Log4j versions 2.0 to 2.14.1.
    The flaw tracked as CVE-2021-44228 allows remote code execution via JNDI injection.
    Attackers are actively exploiting this vulnerability in the wild.
    Affected systems include any Java application using Log4j for logging.
    Users should immediately upgrade to Log4j 2.15.0 or later.
    """
    result = enrich_alert(sample)
    print(json.dumps(result, indent=2))