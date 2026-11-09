# Detections (SPL)

All searches run in Splunk Enterprise against `index=main sourcetype=linux_secure` (source: `/var/log/auth.log`), time range **Last 24 hours**.

## 1. Failed logins by user and source IP

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| stats count by user, src_ip
| sort - count
```

**Why it matters:** repeated failed logins can indicate password guessing or brute force. Attempts against users that do not exist (`invalid user`) often point to username guessing.

**Lab result:** `fakeuser` from `::1` (3), `kali` from `::1` (3).

**Alert:** saved as **Multiple Failed Logins**, scheduled hourly, trigger when results > 0, action: Add to Triggered Alerts.

## 2. New user created

```spl
index=main sourcetype=linux_secure "new user"
```

**Why it matters:** attackers often create accounts to keep access. New accounts should match an approved change.

**Lab result:** `useradd: new user: name=testuser, UID=1002` run by `kali` via `sudo`.

## 3. User added to sudo (admin) group

```spl
index=main sourcetype=linux_secure "to group 'sudo'"
```

**Why it matters:** adding a user to an admin group is privilege escalation or persistence. It should always be verified.

**Lab result:** `usermod: add 'testuser' to group 'sudo'`.

## Ideas to extend
- Add a time window and threshold, for example 5 or more failed logins from one source in 10 minutes, using `bin _time span=10m`.
- Correlate a new user with a sudo group change within a few minutes.
