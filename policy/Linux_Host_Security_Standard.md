# Linux Host Security Standard

| Field | Value |
|---|---|
| Document ID | STD-LNX-001 |
| Version | 1.0 |
| Owner | Security Governance (author: Jainy Gandhi) |
| Review cycle | Annual, or after a significant incident or framework change |
| Applies to | All Linux servers and workstations in scope |
| Framework mapping | CIS Controls v8 |

## 1. Purpose
Define the minimum security configuration for Linux hosts, so that each requirement can be checked automatically and reported as a measurable compliance figure.

## 2. Requirements, control mapping and metrics

| Req ID | Requirement (policy statement) | CIS Controls v8 safeguard | Automated check | Metric |
|---|---|---|---|---|
| ACC-01 | Direct root login over SSH MUST be disabled. | 5.4 Restrict Administrator Privileges to Dedicated Administrator Accounts | `PermitRootLogin no` in sshd config | % of hosts compliant |
| ACC-02 | Only the `root` account MAY have UID 0. | 5.4 | Parse `/etc/passwd` for UID 0 | Count of extra UID 0 accounts (target 0) |
| ACC-03 | Passwords MUST expire within 90 days. | 5.2 Use Unique Passwords | `PASS_MAX_DAYS <= 90` in `/etc/login.defs` | % of hosts compliant |
| ACC-04 | Accounts MUST NOT have an empty password. | 5.2 | Parse `/etc/shadow` | Count of empty-password accounts (target 0) |
| CFG-01 | SSH password authentication MUST be disabled; key-based login only. | 4.1 Establish and Maintain a Secure Configuration Process | `PasswordAuthentication no` | % of hosts compliant |
| FIL-01 | `/etc/passwd` MUST NOT be writable by group or others. | 3.3 Configure Data Access Control Lists | File mode check | % of hosts compliant |
| FIL-02 | `/etc/shadow` MUST NOT be accessible by others or writable by group. | 3.3 | File mode check | % of hosts compliant |
| NET-01 | A host-based firewall MUST be active. | 4.4 Implement and Manage a Firewall on Servers | Service status (ufw / firewalld / nftables) | % of hosts with firewall active |
| NET-02 | Telnet MUST NOT be running. | 4.8 Uninstall or Disable Unnecessary Services | Service status | Count of hosts running telnet (target 0) |
| LOG-01 | An audit or system logging service MUST be active. | 8.2 Collect Audit Logs | Service status (auditd / rsyslog) | % of hosts with logging active |
| PAT-01 | Automatic security updates MUST be enabled. | 7.3 Perform Automated Operating System Patch Management | Service/timer enabled | % of hosts with auto-updates enabled |

## 3. Measurement and reporting
- Compliance % = passed checks / (passed + failed checks). Checks that cannot be evaluated are reported as SKIP and excluded.
- Target: **90% or higher** per host. Anything below 80% is escalated to the system owner.
- Each run is appended to a history file so compliance can be trended over time.

## 4. Exceptions
Exceptions require written approval from the Security Governance owner, a documented compensating control and an expiry date (maximum 6 months).

## 5. Revision history
| Version | Date | Change |
|---|---|---|
| 1.0 | Oct 2026 | Initial release |
