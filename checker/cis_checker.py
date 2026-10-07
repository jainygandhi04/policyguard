#!/usr/bin/env python3
"""
PolicyGuard: Linux host compliance checker.
Evaluates a host against the Linux Host Security Standard (policy/), which is
mapped to CIS Controls v8. Read-only: it never changes system configuration.
"""
import argparse, csv, glob, json, os, platform, subprocess, sys
from datetime import datetime, timezone

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def systemctl(*args):
    if not os.path.isdir("/run/systemd/system"):  # systemd not the running init
        return None
    try:
        r = subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None


def sshd_value(name):
    """Return effective sshd setting (first occurrence wins), 'unset', or None if no sshd_config."""
    if read("/etc/ssh/sshd_config") is None:
        return None
    files = sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")) + ["/etc/ssh/sshd_config"]
    for path in files:
        for line in (read(path) or "").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].lower() == name.lower():
                return parts[1].lower()
    return "unset"


def login_defs(key):
    for line in (read("/etc/login.defs") or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == key:
            return parts[1]
    return None


# ---- Checks: each returns (status, evidence) ----

def ssh_root_login():
    v = sshd_value("PermitRootLogin")
    if v is None:
        return SKIP, "sshd_config not found"
    return (PASS if v == "no" else FAIL), f"PermitRootLogin={v}"


def ssh_password_auth():
    v = sshd_value("PasswordAuthentication")
    if v is None:
        return SKIP, "sshd_config not found"
    return (PASS if v == "no" else FAIL), f"PasswordAuthentication={v}"


def single_uid0():
    data = read("/etc/passwd")
    if data is None:
        return SKIP, "/etc/passwd unreadable"
    uid0 = [l.split(":")[0] for l in data.splitlines() if len(l.split(":")) > 2 and l.split(":")[2] == "0"]
    return (PASS if uid0 == ["root"] else FAIL), f"UID 0 accounts: {', '.join(uid0)}"


def pass_max_days():
    v = login_defs("PASS_MAX_DAYS")
    if v is None or not v.isdigit():
        return FAIL, "PASS_MAX_DAYS not set"
    return (PASS if int(v) <= 90 else FAIL), f"PASS_MAX_DAYS={v}"


def no_empty_passwords():
    data = read("/etc/shadow")
    if data is None:
        return SKIP, "/etc/shadow not readable (run as root)"
    empty = [l.split(":")[0] for l in data.splitlines() if len(l.split(":")) > 1 and l.split(":")[1] == ""]
    return (PASS if not empty else FAIL), f"accounts with empty password: {empty or 'none'}"


def file_mode(path, forbidden_mask):
    def check():
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            return SKIP, f"{path} not found"
        return (PASS if mode & forbidden_mask == 0 else FAIL), f"{path} mode={oct(mode)}"
    return check


def active_any(units, label):
    def check():
        if systemctl("--version") is None:
            return SKIP, "systemd not available"
        found = [u for u in units if systemctl("is-active", u) == "active"]
        return (PASS if found else FAIL), f"{label}: active={found or 'none'}"
    return check


def enabled_any(units, label):
    def check():
        if systemctl("--version") is None:
            return SKIP, "systemd not available"
        found = [u for u in units if systemctl("is-enabled", u) == "enabled"]
        return (PASS if found else FAIL), f"{label}: enabled={found or 'none'}"
    return check


def telnet_disabled():
    if systemctl("--version") is None:
        return SKIP, "systemd not available"
    on = [u for u in ("telnet.socket", "telnetd.service") if systemctl("is-active", u) == "active"]
    return (PASS if not on else FAIL), f"telnet active units: {on or 'none'}"


# (check_id, requirement, CIS Controls v8 safeguard, function)
CHECKS = [
    ("ACC-01", "Direct root SSH login is disabled", "5.4", ssh_root_login),
    ("ACC-02", "Only one UID 0 (root) account exists", "5.4", single_uid0),
    ("ACC-03", "Passwords expire within 90 days", "5.2", pass_max_days),
    ("ACC-04", "No accounts have an empty password", "5.2", no_empty_passwords),
    ("CFG-01", "SSH password authentication is disabled (keys only)", "4.1", ssh_password_auth),
    ("FIL-01", "/etc/passwd is not group/world writable", "3.3", file_mode("/etc/passwd", 0o022)),
    ("FIL-02", "/etc/shadow has no world access, no group write", "3.3", file_mode("/etc/shadow", 0o027)),
    ("NET-01", "A host firewall is active", "4.4", active_any(["ufw", "firewalld", "nftables", "netfilter-persistent"], "firewall")),
    ("NET-02", "Telnet service is not running", "4.8", telnet_disabled),
    ("LOG-01", "Audit/system logging service is active", "8.2", active_any(["auditd", "rsyslog"], "logging")),
    ("PAT-01", "Automatic security updates are enabled", "7.3", enabled_any(["unattended-upgrades", "dnf-automatic.timer", "dnf-automatic-install.timer"], "auto-updates")),
]


def main():
    ap = argparse.ArgumentParser(description="Check a Linux host against the Linux Host Security Standard.")
    ap.add_argument("--json", help="write full report to this JSON file")
    ap.add_argument("--history", help="append a summary row to this CSV (for trend tracking)")
    ap.add_argument("--threshold", type=float, default=80.0, help="exit 1 if compliance %% is below this")
    args = ap.parse_args()

    results = []
    for cid, req, cis, fn in CHECKS:
        status, evidence = fn()
        results.append({"id": cid, "requirement": req, "cis_safeguard": cis, "status": status, "evidence": evidence})

    passed = sum(r["status"] == PASS for r in results)
    failed = sum(r["status"] == FAIL for r in results)
    skipped = sum(r["status"] == SKIP for r in results)
    evaluated = passed + failed
    pct = round(100 * passed / evaluated, 1) if evaluated else 0.0

    print(f"\n{'ID':<8}{'CIS':<6}{'STATUS':<7}REQUIREMENT / EVIDENCE")
    print("-" * 78)
    for r in results:
        print(f"{r['id']:<8}{r['cis_safeguard']:<6}{r['status']:<7}{r['requirement']}")
        print(f"{'':<21}-> {r['evidence']}")
    print("-" * 78)
    print(f"Compliance: {pct}%  (pass={passed}, fail={failed}, skipped={skipped})\n")

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    host = platform.node()
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"host": host, "timestamp": now, "compliance_pct": pct,
                       "passed": passed, "failed": failed, "skipped": skipped, "results": results}, f, indent=2)
    if args.history:
        new = not os.path.exists(args.history)
        with open(args.history, "a", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["timestamp", "host", "compliance_pct", "passed", "failed", "skipped"])
            w.writerow([now, host, pct, passed, failed, skipped])

    sys.exit(0 if pct >= args.threshold else 1)


if __name__ == "__main__":
    main()
