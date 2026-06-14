"""
threat_intel.py — Pipeline 3
Runs every 6 hours. Fetches from NVD, AlienVault OTX, RSS feeds,
and MITRE ATT&CK. Summarizes long entries via Claude API.
Run: cd backend && python -m schedulers.threat_intel
"""
import asyncio
import json
import logging
import os
import sys
import time
import xml.etree.ElementTree as ET  #Python’s built‑in XML parsing libraryim
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime#converts a date string (usually from an email header) into a proper datetime object.
import httpx#modern third‑party HTTP client library for Python. It’s similar to requests, but more powerful because it supports both synchronous and asynchronous usage.
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("threat_intel")

DATABASE_URL   = os.environ["DATABASE_URL"]
NVD_API_KEY    = os.getenv("NVD_API_KEY", "")
OTX_API_KEY    = os.getenv("OTX_API_KEY", "")
GROQ_API_KEY   = os.getenv("GROQ_API_KEY", "")
SLEEP          = int(os.getenv("THREAT_INTEL_SLEEP_SECONDS", str(6 * 3600)))
MOCK_MODE      = os.getenv("THREAT_INTEL_MOCK_MODE", "false").lower() == "true"
LOOKBACK_HOURS = int(os.getenv("THREAT_INTEL_LOOKBACK_HOURS", "6"))

engine  = create_async_engine(DATABASE_URL, pool_size=3, max_overflow=5)
Session = async_sessionmaker(engine, expire_on_commit=False)

RSS_FEEDS = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "TheHackersNews",   "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "DarkReading",      "url": "https://www.darkreading.com/rss.xml"},
]

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


# ── Retry helper ──────────────────────────────────────────────────────────────
#client here means an HTTP client object — a tool for making web requests
async def _get_with_retry(client: httpx.AsyncClient, url: str,
                          headers: dict = None, params: dict = None,
                          max_retries: int = 3,
                          max_rate_limit_retries: int = 3) -> httpx.Response | None:
    delay = 2
    attempt = 0
    rate_limit_attempts = 0
    while attempt < max_retries:
        try:
            r = await client.get(url, headers=headers or {}, params=params or {},
                                 timeout=30)
            if r.status_code == 429:
                if rate_limit_attempts >= max_rate_limit_retries:
                    log.error("Rate limit retries exhausted for %s", url[:60])
                    return None
                wait = int(r.headers.get("Retry-After", delay * 2))
                log.warning("Rate limited by %s — waiting %ss (rate limit attempt %s/%s)",
                            url[:60], wait, rate_limit_attempts + 1, max_rate_limit_retries)
                rate_limit_attempts += 1
                await asyncio.sleep(wait)
                continue  # still doesn't burn a real attempt
            r.raise_for_status()
            return r
        except httpx.HTTPStatusError as exc:
            log.warning("HTTP %s from %s (attempt %s)", exc.response.status_code, url[:60], attempt + 1)
        except httpx.RequestError as exc:
            log.warning("Request error %s (attempt %s): %s", url[:60], attempt + 1, exc)
        attempt += 1  # only real errors count
        await asyncio.sleep(delay)
        delay *= 2
    log.error("All retries exhausted for %s", url[:60])
    return None


# ── Claude summarizer ─────────────────────────────────────────────────────────
async def summarize_with_groq(text_content: str) -> str:
    """Call Groq (llama-3.1-8b-instant) — 2s polite delay, retries once on 429."""
    if not GROQ_API_KEY:
        return text_content[:500]
    if len(text_content) <= 500:
        return text_content

    await asyncio.sleep(2)  # stay within free tier rate limit

    for attempt in range(2):
        try:
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {GROQ_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "llama-3.1-8b-instant",
                        "max_tokens": 200,
                        "messages": [{
                            "role": "user",
                            "content": (
                                "Summarize the following cybersecurity threat intelligence "
                                "in 2-3 sentences. Be factual and concise. Focus on: "
                                "what the threat is, who is affected, and what action is needed.\n\n"
                                f"{text_content[:3000]}"
                            )
                        }]
                    },
                    timeout=30,
                )
                if r.status_code == 429:
                    wait = int(r.headers.get("Retry-After", 10))
                    log.warning("Groq rate limited — waiting %ss", wait)
                    await asyncio.sleep(wait)
                    continue
                r.raise_for_status()
                return r.json()["choices"][0]["message"]["content"].strip()
    # r.json()                      # full API response as dict
    # ["choices"]               # list of response options (usually just one)
    #     [0]                   # first (and only) choice
    #         ["message"]       # the message object
    #             ["content"]   # the actual text the AI wrote
    #                 .strip()  # remove leading/trailing whitespace
        except httpx.HTTPStatusError:
            pass
        except Exception as exc:
            log.warning("Groq summarization failed: %s", exc)
            break

    return text_content[:500]


# ── DB upsert ─────────────────────────────────────────────────────────────────
async def upsert_intel(db, entries: list[dict]) -> int:
    if not entries or MOCK_MODE:
        if MOCK_MODE:
            for e in entries:
                log.info("[MOCK] Would insert: %s — %s", e.get("source"), e.get("title", "")[:60])
        return 0

    inserted = 0
    for entry in entries:
        try:
            result = await db.execute(text("""
                INSERT INTO threat_intel
                    (source, title, summary, url, severity, affected_sectors,
                     attack_types, iocs, published_at, fetched_at)
                VALUES
                    (:source, :title, :summary, :url, :severity,
                     cast(:affected_sectors as jsonb), cast(:attack_types as jsonb),
                     cast(:iocs as jsonb), :published_at, NOW())
                ON CONFLICT (url) DO NOTHING
            """), {
                "source":           entry.get("source", "unknown"),
                "title":            (entry.get("title") or "")[:500],
                "summary":          (entry.get("summary") or "")[:2000],
                "url":              entry.get("url", ""),
                "severity":         entry.get("severity", "medium"),
                "affected_sectors": json.dumps(entry.get("affected_sectors", [])),
                "attack_types":     json.dumps(entry.get("attack_types", [])),
                "iocs":             json.dumps(entry.get("iocs", {})),
                "published_at":     entry.get("published_at"),
            })
            if result.rowcount:
                inserted += 1
        except Exception as exc:
            log.warning("Upsert failed for %s: %s", entry.get("url", "")[:80], exc)

    await db.commit()
    return inserted


# ── NVD CVEs ──────────────────────────────────────────────────────────────────
async def fetch_nvd(client: httpx.AsyncClient) -> list[dict]:
    log.info("Fetching NVD CVEs (last %sh)...", LOOKBACK_HOURS)
    now = datetime.now(timezone.utc)
    pub_start = (now - timedelta(hours=LOOKBACK_HOURS)).strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    r = await _get_with_retry(client,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        headers=headers,
        params={"pubStartDate": pub_start, "pubEndDate": pub_end, "resultsPerPage": 50},
    )
    if not r:
        return []

    entries = []
    try:
        data = r.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score = None
            severity = "medium"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    score = m.get("cvssData", {}).get("baseScore")
                    severity = m.get("cvssData", {}).get("baseSeverity", "MEDIUM").lower()
                    break

            published = cve.get("published")
            pub_dt = None
            if published:
                try:
                    pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except Exception:
                    pass

            summary = await summarize_with_groq(desc) if len(desc) > 500 else desc

            entries.append({
                "source":           "NVD",
                "title":            cve_id,
                "summary":          summary,
                "url":              f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "severity":         severity,
                "affected_sectors": [],
                "attack_types":     [],
                "iocs":             {"cve_ids": [cve_id]},
                "published_at":     pub_dt,
            })
    except Exception as exc:
        log.error("NVD parse error: %s", exc)

    log.info("NVD: %d CVEs fetched", len(entries))
    return entries


# ── AlienVault OTX ────────────────────────────────────────────────────────────
async def fetch_otx(client: httpx.AsyncClient) -> list[dict]:
    if not OTX_API_KEY:
        log.warning("OTX_API_KEY not set — skipping OTX")
        return []

    log.info("Fetching AlienVault OTX pulses...")
    r = await _get_with_retry(client,
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers={"X-OTX-API-KEY": OTX_API_KEY},
        params={"limit": 20, "modified_since":
                (datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)).isoformat()},
    )
    if not r:
        return []

    entries = []
    try:
        data = r.json()
        for pulse in data.get("results", []):
            iocs: dict = {"ips": [], "domains": [], "hashes": [], "urls": []}
            for ind in pulse.get("indicators", []):
                t = ind.get("type", "")
                v = ind.get("indicator", "")
                if t in ("IPv4", "IPv6"):
                    iocs["ips"].append(v)
                elif t == "domain":
                    iocs["domains"].append(v)
                elif t in ("FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"):
                    iocs["hashes"].append(v)
                elif t == "URL":
                    iocs["urls"].append(v)

            desc = pulse.get("description", "")
            summary = await summarize_with_groq(desc) if len(desc) > 500 else desc

            pub_str = pulse.get("created")
            pub_dt = None
            if pub_str:
                try:
                    pub_dt = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                except Exception:
                    pass

            tags = pulse.get("tags", [])
            pulse_id = pulse.get("id", "")

            entries.append({
                "source":           "AlienVault OTX",
                "title":            pulse.get("name", "")[:500],
                "summary":          summary,
                "url":              f"https://otx.alienvault.com/pulse/{pulse_id}",
                "severity":         "medium",
                "affected_sectors": pulse.get("industries", []),
                "attack_types":     tags,
                "iocs":             iocs,
                "published_at":     pub_dt,
            })
    except Exception as exc:
        log.error("OTX parse error: %s", exc)

    log.info("OTX: %d pulses fetched", len(entries))
    return entries


# ── RSS Feeds ─────────────────────────────────────────────────────────────────
async def fetch_rss(client: httpx.AsyncClient) -> list[dict]:
    entries = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)

    for feed in RSS_FEEDS:
        log.info("Fetching RSS: %s", feed["name"])
        r = await _get_with_retry(client, feed["url"])
        if not r:
            continue
        try:
            root = ET.fromstring(r.text)
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            # Handle both RSS and Atom
            items = root.findall(".//item") or root.findall(".//atom:entry", ns)

            for item in items[:20]:
                def _text(tag, default=""):
                    el = item.find(tag) or item.find(f"atom:{tag}", ns)
                    return (el.text or default).strip() if el is not None else default

                title   = _text("title")
                url     = _text("link") or _text("guid")
                desc    = _text("description") or _text("atom:summary", ns) or _text("summary")
                pub_str = _text("pubDate") or _text("published") or _text("atom:published", ns)

                if not url:
                    continue

                pub_dt = None
                if pub_str:
                    try:
                        pub_dt = parsedate_to_datetime(pub_str)
                        if pub_dt.tzinfo is None:
                            pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                    except Exception:
                        try:
                            pub_dt = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                        except Exception:
                            pass

                if pub_dt and pub_dt < cutoff:
                    continue

                summary = await summarize_with_groq(desc) if len(desc) > 500 else desc

                entries.append({
                    "source":           feed["name"],
                    "title":            title[:500],
                    "summary":          summary,
                    "url":              url,
                    "severity":         "medium",
                    "affected_sectors": [],
                    "attack_types":     [],
                    "iocs":             {},
                    "published_at":     pub_dt,
                })
        except ET.ParseError as exc:
            log.error("RSS parse error for %s: %s", feed["name"], exc)
        except Exception as exc:
            log.error("RSS error for %s: %s", feed["name"], exc)

    log.info("RSS: %d articles fetched", len(entries))
    return entries


# ── MITRE ATT&CK ─────────────────────────────────────────────────────────────
async def fetch_mitre(client: httpx.AsyncClient) -> list[dict]:
    log.info("Fetching MITRE ATT&CK enterprise-attack.json...")
    r = await _get_with_retry(client, MITRE_URL)
    if not r:
        return []

    entries = []
    try:
        data = r.json()
        objects = data.get("objects", [])
        # Only grab techniques modified in the last 30 days
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            modified_str = obj.get("modified", "")
            try:
                modified_dt = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
            except Exception:
                continue

            if modified_dt < cutoff:
                continue

            ext_refs = obj.get("external_references", [])
            url = next((r["url"] for r in ext_refs
                        if r.get("source_name") == "mitre-attack" and r.get("url")), "")
            technique_id = next((r.get("external_id", "") for r in ext_refs
                                 if r.get("source_name") == "mitre-attack"), "")
            if not url:
                continue

            desc = obj.get("description", "")
            summary = await summarize_with_groq(desc) if len(desc) > 500 else desc
            tactics = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]

            entries.append({
                "source":           "MITRE ATT&CK",
                "title":            f"{technique_id}: {obj.get('name', '')}",
                "summary":          summary,
                "url":              url,
                "severity":         "medium",
                "affected_sectors": [],
                "attack_types":     tactics,
                "iocs":             {"technique_id": technique_id},
                "published_at":     modified_dt,
            })

    except Exception as exc:
        log.error("MITRE parse error: %s", exc)

    log.info("MITRE ATT&CK: %d recently modified techniques", len(entries))
    return entries


# ── Scheduler status update ───────────────────────────────────────────────────
async def update_status(db, status: str, inserted: int, error: str = None,
                        duration: float = 0.0) -> None:
    await db.execute(text("""
        INSERT INTO scheduler_status
            (process_name, last_run_at, last_run_status, last_error,
             clients_processed, events_inserted, duration_seconds)
        VALUES
            ('threat_intel', NOW(), :status, :error, 0, :inserted, :duration)
        ON CONFLICT (process_name) DO UPDATE SET
            last_run_at      = NOW(),
            last_run_status  = EXCLUDED.last_run_status,
            last_error       = EXCLUDED.last_error,
            events_inserted  = EXCLUDED.events_inserted,
            duration_seconds = EXCLUDED.duration_seconds
    """), {"status": status, "error": error, "inserted": inserted, "duration": duration})
    await db.commit()


# ── Main cycle ────────────────────────────────────────────────────────────────
async def run_cycle() -> None:
    start = time.monotonic()
    total_inserted = 0

    async with httpx.AsyncClient(follow_redirects=True) as http:
        async with Session() as db:
            try:
                # Commit after each source so partial runs save data
                nvd_entries = await fetch_nvd(http)
                total_inserted += await upsert_intel(db, nvd_entries)
                log.info("NVD committed: %d entries", len(nvd_entries))

                otx_entries = await fetch_otx(http)
                total_inserted += await upsert_intel(db, otx_entries)
                log.info("OTX committed: %d entries", len(otx_entries))

                rss_entries = await fetch_rss(http)
                total_inserted += await upsert_intel(db, rss_entries)
                log.info("RSS committed: %d entries", len(rss_entries))

                mitre_entries = await fetch_mitre(http)
                total_inserted += await upsert_intel(db, mitre_entries)
                log.info("MITRE committed: %d entries", len(mitre_entries))

                duration = time.monotonic() - start
                log.info("Cycle complete: %d new inserted (%.1fs)", total_inserted, duration)
                await update_status(db, "success", total_inserted, duration=duration)

            except Exception as exc:
                duration = time.monotonic() - start
                log.exception("Cycle failed: %s", exc)
                await update_status(db, "failed", total_inserted, error=str(exc), duration=duration)


# ── Entry point ───────────────────────────────────────────────────────────────
async def main() -> None:
    log.info("threat_intel.py starting (MOCK_MODE=%s, every %sh)", MOCK_MODE, SLEEP // 3600)
    while True:
        await run_cycle()
        log.info("Sleeping %ds until next cycle...", SLEEP)
        await asyncio.sleep(SLEEP)


if __name__ == "__main__":
    asyncio.run(main())

# {  NVD
#   "vulnerabilities": [
#     {
#       "cve": {
#         "id": "CVE-2024-1234",
#         "published": "2024-01-15T10:30:00.000",
#         "lastModified": "2024-01-15T12:00:00.000",
#         "descriptions": [
#           {
#             "lang": "en",
#             "value": "A buffer overflow vulnerability in Example Software version 1.0 allows remote attackers to execute arbitrary code via a crafted HTTP request to the /admin endpoint. The vulnerability exists due to improper input validation in the authentication module."
#           },
#           {
#             "lang": "es",
#             "value": "Una vulnerabilidad de desbordamiento de búfer..."
#           }
#         ],
#         "metrics": {
#           "cvssMetricV31": [
#             {
#               "cvssData": {
#                 "baseScore": 9.8,
#                 "baseSeverity": "CRITICAL",
#                 "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
#               },
#               "exploitabilityScore": 3.9,
#               "impactScore": 5.9
#             }
#           ]
#         },
#         "references": [
#           {
#             "url": "https://example.com/advisory/2024-001",
#             "source": "vendor"
#           }
#         ]
#       }
#     }
#   ],
#   "totalResults": 1,
#   "resultsPerPage": 50
# }

# {  AlienVault
#   "results": [
#     {
#       "id": "65a3f2b8c4d5e6f7a8b9c0d1",
#       "name": "Lazarus Group Campaign Targeting Financial Institutions",
#       "description": "A sophisticated threat actor known as Lazarus Group has been observed conducting spear-phishing campaigns targeting financial institutions in Southeast Asia. The campaign uses malicious Excel documents with embedded macros that download a custom backdoor. The backdoor communicates with C2 servers using encrypted HTTP traffic on port 443. Multiple banks in the region have reported incidents consistent with this campaign pattern.",
#       "created": "2024-01-15T08:30:00Z",
#       "modified": "2024-01-15T10:00:00Z",
#       "tags": [
#         "apt",
#         "lazarus",
#         "financial",
#         "spearphishing",
#         "backdoor"
#       ],
#       "industries": [
#         "Finance",
#         "Banking"
#       ],
#       "indicators": [
#         {
#           "type": "IPv4",
#           "indicator": "203.0.113.45",
#           "description": "C2 server"
#         },
#         {
#           "type": "IPv6",
#           "indicator": "2001:db8::1",
#           "description": "Secondary C2"
#         },
#         {
#           "type": "domain",
#           "indicator": "malicious-update.com",
#           "description": "Phishing domain"
#         },
#         {
#           "type": "FileHash-MD5",
#           "indicator": "d41d8cd98f00b204e9800998ecf8427e",
#           "description": "Malicious Excel file"
#         },
#         {
#           "type": "FileHash-SHA256",
#           "indicator": "e3b0c44298fc1c149afbf4c8996fb924",
#           "description": "Backdoor binary"
#         },
#         {
#           "type": "URL",
#           "indicator": "http://malicious-update.com/payload.exe",
#           "description": "Payload download URL"
#         }
#       ]
#     }
#   ],
#   "count": 1,
#   "next": null,
#   "previous": null
# }
# <?xml version="1.0" encoding="UTF-8"?>   #RSS XML
# <rss version="2.0">
#   <channel>
#     <title>BleepingComputer</title>
#     <link>https://www.bleepingcomputer.com</link>
#     <description>BleepingComputer - Security News</description>
    
#     <item>
#       <title>New Ransomware Group Targets Healthcare Organizations</title>
#       <link>https://www.bleepingcomputer.com/news/security/new-ransomware-targets-healthcare/</link>
#       <guid>https://www.bleepingcomputer.com/news/security/new-ransomware-targets-healthcare/</guid>
#       <pubDate>Mon, 15 Jan 2024 08:30:00 +0000</pubDate>
#       <description>
#         A new ransomware group called BlackMedic has been observed targeting 
#         healthcare organizations across Europe and North America. The group 
#         exploits unpatched VPN vulnerabilities to gain initial access, then 
#         deploys a custom ransomware payload that encrypts patient records...
#         (500+ characters of article text)
#       </description>
#     </item>

#     <item>
#       <title>Critical RCE Vulnerability Found in Apache Log4j</title>
#       <link>https://www.bleepingcomputer.com/news/security/critical-rce-log4j/</link>
#       <guid>https://www.bleepingcomputer.com/news/security/critical-rce-log4j/</guid>
#       <pubDate>Mon, 15 Jan 2024 06:00:00 +0000</pubDate>
#       <description>Short description under 500 chars.</description>
#     </item>

#   </channel>
# </rss>

# {  #MITRE
#   "type": "bundle",
#   "id": "bundle--1234",
#   "objects": [
#     {
#       "type": "attack-pattern",
#       "id": "attack-pattern--abc123",
#       "name": "Spearphishing Attachment",
#       "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email...(very long description)",
#       "modified": "2024-01-10T15:00:00.000Z",
#       "created": "2020-03-02T19:05:18.137Z",
#       "revoked": false,
#       "x_mitre_deprecated": false,
#       "kill_chain_phases": [
#         {
#           "kill_chain_name": "mitre-attack",
#           "phase_name": "initial-access"
#         }
#       ],
#       "external_references": [
#         {
#           "source_name": "mitre-attack",
#           "url": "https://attack.mitre.org/techniques/T1566/001",
#           "external_id": "T1566.001"
#         },
#         {
#           "source_name": "SANS",
#           "url": "https://www.sans.org/some-reference",
#           "description": "Additional reference"
#         }
#       ]
#     },
#     {
#       "type": "attack-pattern",
#       "id": "attack-pattern--def456",
#       "name": "PowerShell",
#       "description": "Adversaries may abuse PowerShell commands and scripts for execution...",
#       "modified": "2024-01-12T10:00:00.000Z",
#       "revoked": false,
#       "x_mitre_deprecated": false,
#       "kill_chain_phases": [
#         {
#           "kill_chain_name": "mitre-attack",
#           "phase_name": "execution"
#         }
#       ],
#       "external_references": [
#         {
#           "source_name": "mitre-attack",
#           "url": "https://attack.mitre.org/techniques/T1059/001",
#           "external_id": "T1059.001"
#         }
#       ]
#     },
#     {
#       "type": "intrusion-set",
#       "id": "intrusion-set--ghi789",
#       "name": "Lazarus Group"
#     },
#     {
#       "type": "malware",
#       "id": "malware--jkl012",
#       "name": "WannaCry",
#       "revoked": true
#     },
#     {
#       "type": "course-of-action",
#       "id": "course-of-action--mno345",
#       "name": "Some mitigation"
#     }
#   ]
# }