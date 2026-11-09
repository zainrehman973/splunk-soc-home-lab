# Incident Report: INC-LAB-001

> **Simulated incident.** I created this activity myself on my own lab VM to practise Tier 1 triage and documentation. No real systems or users were affected.

| Field | Detail |
|-------|--------|
| Ticket ID | INC-LAB-001 |
| Title | Failed SSH logins followed by new admin account creation |
| Date | 7 Nov 2026 (times as shown in Splunk, UTC-05:00) |
| Detected by | Splunk alert **Multiple Failed Logins**, then analyst review |
| Host | `kali` (lab VM) |
| Log source | `/var/log/auth.log` (`linux_secure`) |
| Severity | Medium (would be High on a production server) |
| Status | Escalated (simulated) |

## 1. Summary
Splunk logged repeated failed SSH logins against a non-existent user (`fakeuser`) and the real user `kali`. About 30 seconds later, a new local account (`testuser`) was created and added to the `sudo` group. Together, the activity looks like password guessing followed by account creation and privilege escalation, a common pattern after a successful compromise.

## 2. Timeline

| Time | Event |
|------|-------|
| 14:05:41 | Failed SSH authentication for `kali` from `::1` (PAM reports more authentication failures) |
| 14:06:05 | `sudo` used by `kali` to run `useradd testuser` |
| 14:06:05 | New user created: `name=testuser, UID=1002, home=/home/testuser, shell=/bin/sh` |
| 14:06:05 | `sudo` used by `kali` to run `usermod -aG sudo testuser` |
| 14:06:05 | `testuser` added to group `sudo` (and the `sudo` shadow group) |

## 3. Evidence
Screenshots are in the `screenshots/` folder:
- `04-failed-logins.png`: failed logins grouped by user and source IP
- `05-new-user.png`: new user creation
- `06-sudo-group.png`: sudo group change
- `07-dashboard.png`: dashboard overview

## 4. Analysis
- **Failed logins:** three failures for `fakeuser` (invalid user) and three for `kali`. Attempts on a user that does not exist suggest username guessing.
- **Source:** `::1` is IPv6 localhost, which is expected because this was a lab test. In a real case, an external source IP would need checking against threat intelligence and the firewall logs.
- **New account and sudo membership:** an unapproved account with admin rights gives an attacker persistence and full control, so it is high risk even if the logins failed.
- **Not confirmed:** whether any login succeeded. I would check for `Accepted password` events for the same accounts.

## 5. Recommended actions
1. Check for successful logins after the failures: search `Accepted password` for `kali` and `testuser`.
2. Verify whether the creation of `testuser` was an approved change.
3. If not approved: disable the account (`usermod -L testuser`), remove it from `sudo`, and review what it did.
4. Reset the password for `kali` and check for other changes (cron jobs, SSH keys, new services).
5. Block the source IP if it were external, and review SSH exposure and rate limiting.
6. Escalate to a senior analyst with this timeline and evidence.

## 6. Lessons and tuning
- The alert threshold (more than 0 results) is low for lab purposes. A real alert should use a time window and count, for example 5 or more failures from one source in 10 minutes.
- Add a second alert that correlates a new user and a sudo group change within a short period.
- Forward logs from more hosts to see the full attack path.

## MITRE ATT&CK
- T1110.001 Brute Force: Password Guessing
- T1136.001 Create Account: Local Account
- T1098 Account Manipulation
