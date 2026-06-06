import json
import uuid
from datetime import datetime, timezone
import stix2


def generate_stix_bundle(alert: dict, enriched: dict) -> str:
    """
    Takes raw alert metadata + AI enriched data and returns a STIX 2.1 bundle as JSON string.

    alert = {alert_id, title, url, published_at}
    enriched = {severity, threat_type, summary, affected_systems, cves, iocs, attack_patterns, recommendations}
    """

    now        = datetime.now(timezone.utc)
    objects    = []
    refs       = []

    # ------------------------------------------------------------------ #
    # 1. IDENTITY — the source organization (CSK)
    # ------------------------------------------------------------------ #
    identity = stix2.Identity(
        id             = "identity--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, "csk.gov.in")),
        name           = "Cyber Swachhta Kendra (CSK)",
        identity_class = "organization",
        description    = "Indian Government Cybersecurity Portal",
    )
    objects.append(identity)

    # ------------------------------------------------------------------ #
    # 2. VULNERABILITY objects — one per CVE
    # ------------------------------------------------------------------ #
    cves = enriched.get("cves", [])
    for cve in cves:
        cve = cve.strip()
        if not cve.startswith("CVE-"):
            continue
        vuln = stix2.Vulnerability(
            id          = "vulnerability--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, cve)),
            name        = cve,
            description = f"Vulnerability {cve} identified in CSK alert: {alert.get('title', '')}",
            external_references=[
                stix2.ExternalReference(
                    source_name = "CVE",
                    external_id = cve,
                    url         = f"https://nvd.nist.gov/vuln/detail/{cve}"
                )
            ],
            created_by_ref = identity.id,
        )
        objects.append(vuln)
        refs.append(vuln.id)

    # ------------------------------------------------------------------ #
    # 3. MALWARE object — if threat type is malware related
    # ------------------------------------------------------------------ #
    threat_type = enriched.get("threat_type", "").lower()
    malware_keywords = ["malware", "ransomware", "trojan", "virus", "worm", "spyware", "botnet"]

    if any(kw in threat_type for kw in malware_keywords):
        malware = stix2.Malware(
            id          = "malware--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, alert.get("alert_id", str(uuid.uuid4())))),
            name        = alert.get("title", "Unknown Malware"),
            description = enriched.get("summary", ""),
            is_family   = False,
            malware_types = [threat_type if threat_type in [
                "ransomware", "trojan", "virus", "worm", "spyware", "botnet", "backdoor"
            ] else "malware"],
            created_by_ref = identity.id,
        )
        objects.append(malware)
        refs.append(malware.id)

    # ------------------------------------------------------------------ #
    # 4. ATTACK PATTERN — MITRE style
    # ------------------------------------------------------------------ #
    for pattern in enriched.get("attack_patterns", []):
        if not pattern.strip():
            continue
        ap = stix2.AttackPattern(
            id          = "attack-pattern--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, pattern)),
            name        = pattern,
            description = f"Attack pattern observed in alert: {alert.get('title', '')}",
            created_by_ref = identity.id,
        )
        objects.append(ap)
        refs.append(ap.id)

    # ------------------------------------------------------------------ #
    # 5. INDICATORS — IPs, Domains, URLs, Hashes
    # ------------------------------------------------------------------ #
    iocs = enriched.get("iocs", {})

    for ip in iocs.get("ips", []):
        ip = ip.strip()
        if not ip:
            continue
        try:
            indicator = stix2.Indicator(
                id          = "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, ip)),
                name        = f"Malicious IP: {ip}",
                pattern     = f"[ipv4-addr:value = '{ip}']",
                pattern_type= "stix",
                indicator_types = ["malicious-activity"],
                valid_from  = now,
                created_by_ref = identity.id,
            )
            objects.append(indicator)
            refs.append(indicator.id)
        except Exception:
            pass

    for domain in iocs.get("domains", []):
        domain = domain.strip()
        if not domain:
            continue
        try:
            indicator = stix2.Indicator(
                id          = "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, domain)),
                name        = f"Malicious Domain: {domain}",
                pattern     = f"[domain-name:value = '{domain}']",
                pattern_type= "stix",
                indicator_types = ["malicious-activity"],
                valid_from  = now,
                created_by_ref = identity.id,
            )
            objects.append(indicator)
            refs.append(indicator.id)
        except Exception:
            pass

    for h in iocs.get("hashes", []):
        h = h.strip()
        if not h:
            continue
        try:
            indicator = stix2.Indicator(
                id          = "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, h)),
                name        = f"Malicious Hash: {h}",
                pattern     = f"[file:hashes.MD5 = '{h}']",
                pattern_type= "stix",
                indicator_types = ["malicious-activity"],
                valid_from  = now,
                created_by_ref = identity.id,
            )
            objects.append(indicator)
            refs.append(indicator.id)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # 6. REPORT — wraps everything together
    # ------------------------------------------------------------------ #
    report = stix2.Report(
        id          = "report--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, alert.get("alert_id", str(uuid.uuid4())))),
        name        = alert.get("title", "CSK Alert"),
        description = enriched.get("summary", ""),
        published   = now,
        report_types= ["threat-report"],
        object_refs = refs if refs else [identity.id],
        created_by_ref = identity.id,
        external_references=[
            stix2.ExternalReference(
                source_name = "Cyber Swachhta Kendra",
                url         = alert.get("url", "https://www.csk.gov.in")
            )
        ],
        labels = [
            enriched.get("severity", "Unknown").lower(),
            enriched.get("threat_type", "Unknown").lower(),
        ],
    )
    objects.append(report)

    # ------------------------------------------------------------------ #
    # 7. Build the BUNDLE
    # ------------------------------------------------------------------ #
    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    return bundle.serialize(pretty=True)


if __name__ == "__main__":
    # Quick test with dummy data
    sample_alert = {
        "alert_id":     "test-alert-001",
        "title":        "Critical Vulnerability in Apache Log4j",
        "url":          "https://www.csk.gov.in/alerts/test.html",
        "published_at": "2024-01-01",
    }
    sample_enriched = {
        "severity":         "Critical",
        "threat_type":      "Vulnerability",
        "summary":          "A critical RCE vulnerability exists in Apache Log4j allowing remote attackers to execute arbitrary code.",
        "affected_systems": ["Apache Log4j 2.x", "Java applications"],
        "cves":             ["CVE-2021-44228"],
        "iocs":             {
            "ips":     ["192.168.1.100"],
            "domains": ["malicious-domain.com"],
            "hashes":  [],
            "urls":    []
        },
        "attack_patterns":  ["Remote Code Execution", "JNDI Injection"],
        "recommendations":  "Upgrade to Log4j 2.15.0 or later immediately."
    }

    bundle_json = generate_stix_bundle(sample_alert, sample_enriched)
    print(bundle_json)