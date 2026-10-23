# Rocky Linux Lab

A hands-on home lab: one Rocky Linux server in a virtual machine, built,
administered, hardened, and used to run a database and my own security tools.

I built this to get real, documented practice with Linux administration,
host hardening, and SQL. It is a lab, not a production environment, and
everything below is what I actually did and saw.

## Environment

- Host: Windows desktop, VirtualBox 7.2
- Guest: Rocky Linux 10.2 (Red Quartz), Server install, root account disabled, one admin user in `wheel`
- VM: 4 GB RAM, 2 vCPUs, 40 GB disk (LVM), NAT networking with an SSH port forward (host 2222 to guest 22)
- Installer ISO verified against its published SHA-256 checksum before install

## What I did

### 1. Build
Installed Rocky 10.2 with the Server software selection and automatic LVM partitioning. I
disabled the root account in the installer and created an administrator user instead.
The root filesystem is a 34 GB logical volume with a separate 2 GB `/boot`. The VM booted
cleanly on the first try.

### 2. Administer
- **Patching:** `dnf upgrade` installed or updated 235 packages (`dnf history` shows the original 669-package install and the upgrade as separate transactions). `rpm -q kernel` listed a newer kernel than `uname -r` was running, so I rebooted and confirmed the change: `6.12.0-211.16.1` before, `6.12.0-211.67.1` after.
- **Users and permissions:** created `labuser`, added it to `wheel`, and checked it with `id` and `sudo -l -U`. Created `/srv/lab` owned by `labuser` with mode 750, confirmed with `stat` (`750 labuser:labuser`). Tested it as an unrelated user: `sudo -u nobody ls /srv/lab` returned `Permission denied`.
- **Services and logs:** confirmed `sshd` active and enabled, read `journalctl -p err -b`. The errors were expected VM noise: a CPU RETBleed mitigation warning (a property of the host CPU), "unmaintained driver" warnings for legacy NIC and storage drivers, and a VMware graphics driver complaining about the VirtualBox hypervisor. I left them alone rather than chasing them.
- **Resources:** checked `df -h` and `free -h`: root 8% used, 3.1 GiB memory available.

### 3. Harden
- **SSH:** generated an ed25519 key with a passphrase, installed the public key, and tested key login. Then I created `/etc/ssh/sshd_config.d/00-lab.conf` with `PermitRootLogin no` and `PasswordAuthentication no`. sshd uses the first value it finds for a setting, so I named the file `00-` to make sure it is read first, and confirmed the effective values with `sshd -T`. Test: key login works; with `-o PubkeyAuthentication=no` the server answers `Permission denied (publickey,gssapi-keyex,gssapi-with-mic)` and never offers a password prompt.
- **firewalld:** active, default `public` zone. The defaults allowed `ssh`, `cockpit` (the web admin console on port 9090) and `dhcpv6-client`. Nothing needed the console, so I removed `cockpit` from the zone (`--permanent --remove-service=cockpit`, then reload); only `ssh` and `dhcpv6-client` remain, in both the running and the saved configuration. `cockpit.socket` is also disabled.
- **SELinux:** `Enforcing`, `targeted` policy, enforcing in the config file as well so it survives reboot. `ausearch -m avc -ts recent` returned no denials.
- **auditd:** active and enabled.

What each control protects against:
- **SSH keys, no passwords:** password guessing cannot succeed because there is no password to guess. An attacker needs the private key and its passphrase.
- **No root login:** takes away the most predictable account name to attack, and ties admin actions to a named user through `sudo`, so they are logged under that user.
- **firewalld:** only listed services are reachable, so a service that starts listening later is not exposed by accident. Unused defaults like the cockpit console are extra attack surface.
- **SELinux:** limits what a compromised service can read or do, as a second layer behind ordinary file permissions.
- **auditd:** records security-relevant events so there is something to investigate afterward.

### 4. Database
Installed PostgreSQL 16.15 from the Rocky repositories, initialized it, and created a `vulnlab` database with a `labuser` role (password set with `\password`, not typed into a statement). TCP logins failed at first with `Ident authentication failed` because `pg_hba.conf` defaults to `ident` for local TCP connections. I changed the `127.0.0.1/32` and `::1/128` lines from `ident` to `scram-sha-256`, left the local socket and replication lines alone, and restarted the service.

I loaded the sample findings from my [vuln-prioritizer](https://github.com/Tbrug71/vuln-prioritizer) project into a `findings` table (`\copy` reported 15 rows) and ran the same logic in SQL:

```sql
SELECT severity, count(*) FROM findings GROUP BY severity ORDER BY count(*) DESC;
-- Medium 4, High 4, Critical 4, Low 3
```

An overdue-against-SLA query (Critical 15, High 30, Medium 60, Low 90 days) returned 14 of 15 findings, Critical first and oldest first within each severity. Running `vuln-prioritizer` on the same CSV the same day gave the same result: 14 overdue, the same ages, the same order, and the same single on-time finding (an OpenSSH finding at 59 of 60 days). That checks that the two implementations are consistent. Both use the SLA rules I chose, so it does not validate the SLA policy itself. Most findings are overdue only because the sample dates are old.

### 5. Detection on real logs
I temporarily enabled password login, generated failed and successful SSH logins from my Windows host, then turned password login off again and confirmed it with `sshd -T`. I ran my [log analyzer](https://github.com/Tbrug71/log-analyzer) on the server's real `/var/log/secure`.

**First run: 0 auth events.** The log contained failed logins, but the analyzer reported nothing: `Auth events analyzed: 0 (ignored 18 other sshd lines, 227 unparseable)`. Cause: current OpenSSH logs login handling under the process name `sshd-session[...]`, and my line pattern only matched `sshd[...]`. A one-line regex fix (`sshd(?:-session)?`) corrected it, and I committed it to the analyzer repo. The tool had failed quietly, which would look like "no attacks" if I had not checked the unparseable count.

**After the fix,** the log's 3 failed passwords (one username, one connection) correctly produced no findings, since the defaults need 5 failures for brute force and 4 distinct invalid usernames for enumeration. A larger test produced:

```
Auth events analyzed: 19
Findings: 2  (HIGH 1 | MEDIUM 1 | LOW 0)

[HIGH]   Success after failures - 10.0.2.2 (user: tom)
[MEDIUM] Brute force - 10.0.2.2 - 6 failed logins within 10 min; users targeted: baduser, admin
```

What the analyzer got wrong or missed:
- **False positive:** the HIGH finding is my own normal key login. With VirtualBox NAT, every connection from my host appears as `10.0.2.2`, so the attacker and the legitimate admin share one IP and the "success after failures" rule cannot tell them apart. It would behave the same for users behind a shared NAT or proxy in production.
- **Missed signal:** every attempt starts with an `Invalid user ...` line, which the analyzer ignores. It only counts `Failed password` lines, so a scan that tries a username and disconnects before the password step would not be seen.
- **Misleading label:** the "unparseable" count is mostly non-SSH lines (`sudo`, system messages) that also land in `/var/log/secure`, not malformed SSH lines.
- Username enumeration was not triggered in my tests (only 2 distinct names); I did not test that rule on the VM.

## What I learned

- A patch is not applied until the running system is on it: `rpm -q kernel` and `uname -r` can disagree, and a reboot plus a check closes the gap.
- A detection tool that returns zero is not the same as a clean system. Checking the parsed and unparsed counts is what exposed the `sshd-session` problem.
- Hardening has to be verified, not assumed. `sshd -T` showed the effective settings, and a failed password-only login was the proof the control worked.
- The first database login failing was an authentication-method setting (`ident` vs `scram-sha-256`), not a bad password, and the fix was a two-line change.
- Network addressing affects detection: behind NAT, source-IP logic can mislabel normal activity.

## Limitations

- Single VM, no production traffic, no monitoring stack
- Lab practice, not production experience
- Sample vulnerability data is fictional; the SQL cross-check shows consistency between two of my tools, not that the SLA policy is correct
- Log analyzer tested on a small, self-generated log from a single source IP
- Not yet covered: Ansible automation, monitoring (Prometheus/Grafana), backups

## Next steps

- Automate the SSH, firewall and SELinux checks with an Ansible playbook
- Add monitoring
- Improve the log analyzer: handle `Invalid user` lines, weigh password vs key successes in the success-after-failures rule, and relabel the "unparseable" count

## Related projects

- [vuln-prioritizer](https://github.com/Tbrug71/vuln-prioritizer): ranks vulnerability scan findings by severity and SLA age
- [log-analyzer](https://github.com/Tbrug71/log-analyzer): flags suspicious SSH login activity
