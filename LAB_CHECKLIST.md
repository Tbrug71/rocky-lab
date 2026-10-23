# Rocky Linux Lab: Checklist

Work through these in order. After each phase, take a VirtualBox snapshot
(Machine > Take Snapshot) and paste your real output into README.md.
Only write down what you actually did and saw.

Conventions: `$` = run as your normal user, `sudo` = run as admin.
Version used: Rocky Linux 10.2 (if you fell back to Rocky 9, the steps are the same).

---

## Phase 1: Build

- [ ] ISO downloaded and SHA-256 hash matches the CHECKSUM file
- [ ] VirtualBox installed
- [ ] VM `rocky-lab` created (4096 MB RAM, 2 CPUs, 40 GB disk, NAT network, "Skip Unattended Installation" checked)
- [ ] Rocky installed with the **Server** software selection, root password set, your own admin user created
- [ ] Logged in as your own user
- [ ] Snapshot: `01-fresh-install`

First commands to run and save the output of:

```bash
cat /etc/os-release
uname -r
hostnamectl
```

---

## Phase 2: Administer

Goal: prove day-to-day Linux administration.

**Updates and packages**
```bash
sudo dnf check-update
sudo dnf upgrade -y
dnf history
dnf info postgresql-server     # note the version available (Rocky 10.2 gave PostgreSQL 16.15)
```

**Users, groups, sudo**
```bash
sudo useradd -m labuser
sudo passwd labuser
sudo usermod -aG wheel labuser
id labuser
sudo -l -U labuser
```

**Permissions**
```bash
sudo mkdir /srv/lab
sudo chown labuser:labuser /srv/lab
sudo chmod 750 /srv/lab
ls -ld /srv/lab
```

**Services (systemd)**
```bash
systemctl status sshd
systemctl list-units --type=service --state=running
sudo systemctl enable --now chronyd
systemctl is-enabled chronyd
```

**Logs**
```bash
journalctl -u sshd --since "1 hour ago"
journalctl -p err -b
```

**Resources and storage**
```bash
df -h
free -h
lsblk
top            # press q to quit
```

- [ ] Snapshot: `02-administered`
- [ ] README: write 3-4 sentences on what you did and one thing that surprised you

---

## Phase 3: Harden

Goal: prove basic host security.

**Set up SSH from Windows (port forward)**
1. VM powered off: Settings > Network > Adapter 1 > Advanced > Port Forwarding
2. Add a rule: Name `ssh`, Protocol TCP, Host IP blank, Host Port `2222`, Guest Port `22`
3. Start the VM. In Windows PowerShell:

```powershell
ssh -p 2222 YOURUSER@127.0.0.1
```

**Key-based login (in Windows PowerShell)**
```powershell
ssh-keygen -t ed25519
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh -p 2222 YOURUSER@127.0.0.1 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
ssh -p 2222 YOURUSER@127.0.0.1    # should log in without a password
```

**Lock down SSH**: keep a second session open while testing so you cannot lock yourself out.
```bash
sudo nano /etc/ssh/sshd_config.d/00-lab.conf   # 00- so it is read first; sshd uses the first value it finds
```
Put these lines in the file:
```
PermitRootLogin no
PasswordAuthentication no
```
Then:
```bash
sudo sshd -t                      # checks syntax, prints nothing if OK
sudo systemctl reload sshd
```

**Firewall (firewalld)**
```bash
sudo firewall-cmd --state
sudo firewall-cmd --list-all
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

**SELinux: leave it Enforcing**
```bash
getenforce
sestatus
ls -Z /srv/lab
sudo ausearch -m avc -ts recent
```

**Audit service**
```bash
sudo systemctl status auditd
```

- [ ] Snapshot: `03-hardened`
- [ ] README: what each setting protects against, in your own words

---

## Phase 4: Database (PostgreSQL + SQL)

Goal: prove practical familiarity with relational databases.

**Install and start**
```bash
sudo dnf install -y postgresql-server
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
sudo -u postgres psql -c "SELECT version();"
```

**Create a database and user**
```bash
sudo -u postgres psql
```
```sql
CREATE DATABASE vulnlab;
CREATE USER labuser WITH PASSWORD 'choose-a-password';
GRANT ALL PRIVILEGES ON DATABASE vulnlab TO labuser;
\c vulnlab
GRANT ALL ON SCHEMA public TO labuser;
\q
```

**Copy your vuln-prioritizer sample data into the VM (from Windows PowerShell)**
```powershell
scp -P 2222 C:\Users\USER\OneDrive\Documents\vuln-prioritizer\sample_vulnerabilities.csv YOURUSER@127.0.0.1:~
```
(Adjust the path to wherever your vuln-prioritizer folder is.)

**Create the table and load the CSV**
```bash
psql -h 127.0.0.1 -U labuser -d vulnlab
```
```sql
CREATE TABLE findings (
  host text,
  vulnerability_id text,
  title text,
  severity text,
  first_detected date
);
\copy findings FROM 'sample_vulnerabilities.csv' CSV HEADER
SELECT count(*) FROM findings;
```

If the login fails with "Ident authentication failed", edit
`/var/lib/pgsql/data/pg_hba.conf` and change `ident` to `scram-sha-256` for
the 127.0.0.1 line, then `sudo systemctl restart postgresql`.

**Queries to run and save (these mirror what vuln-prioritizer does)**
```sql
-- count by severity
SELECT severity, count(*) FROM findings GROUP BY severity ORDER BY count(*) DESC;

-- age of each finding
SELECT host, title, severity, (CURRENT_DATE - first_detected) AS age_days
FROM findings ORDER BY age_days DESC;

-- overdue against the SLA windows (Critical 15, High 30, Medium 60, Low 90)
SELECT * FROM (
  SELECT host, title, severity,
         (CURRENT_DATE - first_detected) AS age_days,
         CASE severity WHEN 'Critical' THEN 15 WHEN 'High' THEN 30
                       WHEN 'Medium' THEN 60 ELSE 90 END AS sla_days
  FROM findings
) t
WHERE age_days > sla_days
ORDER BY severity, age_days DESC;
```

- [ ] Snapshot: `04-database`
- [ ] README: paste one query and its output

---

## Phase 5: Run your log analyzer on real logs

**Generate real failed and successful logins.** From Windows PowerShell:
```powershell
ssh -p 2222 baduser@127.0.0.1     # try this 6 or 7 times with wrong passwords
ssh -p 2222 root@127.0.0.1        # try a few times
```
(You turned password logins off in Phase 3. For this test, temporarily set
`PasswordAuthentication yes` in the drop-in file, reload sshd, run the tests,
then set it back to `no` and reload.)

**Get the log**
```bash
sudo ls /var/log/secure
```
If that file does not exist, export the journal instead:
```bash
sudo journalctl -u sshd --no-pager -o short > ~/sshd.log
```

**Copy your analyzer into the VM and run it**
```powershell
scp -P 2222 C:\Users\USER\projects\log-analyzer\log_analyzer.py YOURUSER@127.0.0.1:~
```
```bash
sudo python3 log_analyzer.py --input /var/log/secure --year 2026 --output findings.csv
```

**Likely problem: zero events found.** Newer OpenSSH versions name the login
process `sshd-session` instead of `sshd`, so log lines read
`sshd-session[1234]:`. The analyzer currently only matches `sshd[1234]:`.
If the summary says 0 auth events, open the log, confirm that is the cause,
and tell me. The fix is a one-line change in `LINE_RE`.

- [ ] Snapshot: `05-analyzer`
- [ ] README: paste the summary output and note anything the analyzer got wrong

---

## Phase 6: Publish

```powershell
cd C:\Users\USER\projects\rocky-lab
git init
git add LAB_CHECKLIST.md README.md
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/Tbrug71/rocky-lab.git
git push -u origin main
```
Add screenshots and command output as you go. Do not commit passwords,
private keys, or anything from your employer.

- [ ] README complete, public repo checked in an incognito window
- [ ] Pinned on GitHub profile
