# PolicyGuard: Linux Compliance Checker

Turns a written security standard into automated, measurable checks.

Most security policies stay on paper. This project shows the full path from **policy statement, to framework mapping, to automated check, to compliance metric**.

## What's in this repo

| Path | Purpose |
|---|---|
| `policy/Linux_Host_Security_Standard.md` | A short security standard with 11 requirements, each mapped to a CIS Controls v8 safeguard and a metric |
| `checker/cis_checker.py` | Python script (standard library only) that checks a Linux host against the standard |

## How it works

1. Each requirement in the standard has an ID (e.g. `ACC-01`) and a CIS safeguard.
2. `cis_checker.py` implements one check per requirement ID. Checks are read-only.
3. Each check returns `PASS`, `FAIL` or `SKIP` (cannot be evaluated, e.g. not root, or no systemd) with evidence.
4. The script computes **compliance % = passed / (passed + failed)**, writes an optional JSON report, and appends to a CSV history file for trend tracking.
5. The exit code is non-zero if compliance falls below a threshold, so it can run in a CI job or scheduled task.

## Usage

```bash
python3 checker/cis_checker.py                       # console report
sudo python3 checker/cis_checker.py --json report.json --history history.csv
python3 checker/cis_checker.py --threshold 90        # exit 1 if below 90%
```

Run with `sudo` to evaluate checks that need to read `/etc/shadow`; otherwise they are marked `SKIP`.

## Example output (excerpt)

```
ID      CIS   STATUS REQUIREMENT / EVIDENCE
ACC-02  5.4   PASS   Only one UID 0 (root) account exists
                     -> UID 0 accounts: root
ACC-03  5.2   FAIL   Passwords expire within 90 days
                     -> PASS_MAX_DAYS=99999
...
Compliance: 55.6%  (pass=5, fail=4, skipped=2)
```

## Limitations and next steps

- The checks cover a small subset of CIS Controls; this is a prototype, not a full CIS Benchmark scanner.
- Single host only. Next step: run across multiple hosts (e.g. over SSH or via configuration management) and chart `history.csv` in a dashboard.
- Possible extension: cloud checks (e.g. IAM or storage settings) using the same requirement-to-check structure.
- AI usage: Claude was used to draft the initial requirement-to-safeguard mapping and check logic; every mapping and check was reviewed and tested manually.

## Results (Kali Linux test host)

| Run | Compliance | Pass | Fail |
|---|---|---|---|
| Baseline | 54.5% | 6 | 5 |
| After firewall, patching, password aging and SSH fixes (partial) | 90.9% | 10 | 1 |
| After enabling the firewall service | 100% | 11 | 0 |

Raw reports and trend history are in `evidence/`. The five findings fixed were the host firewall, SSH root login, SSH password authentication, password aging and automatic updates.
