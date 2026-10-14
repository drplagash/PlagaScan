# PlagaScan

![PlagaScan - cover](docs/cover.jpg)

A **read-only, zero-dependency** Linux hardening auditor (Python 3.8+, standard library only).
In seconds it checks the things that most often open the door to a local or remote attacker, and tells you how to fix them.

```
$ sudo plagascan --min-severity high
Puntaje: 56/100  Nota: D
CRITICAL=0  HIGH=3  MEDIUM=1  LOW=10  INFO=7

[HIGH    ] Miembros del grupo 'docker' (equivalente a root) [ACC-006]
    Quien pertenece a este grupo puede montar / en un contenedor y leer/escribir todo el host.
      - alice
    Arreglo: Quitar del grupo a quien no lo necesite.
    Ref: https://gtfobins.github.io/gtfobins/docker/

[HIGH    ] VNC expuesto en tcp/5901 [NET-002]
    VNC suele tener autenticación débil.
      - 0.0.0.0:5901 Xtigervnc
    Arreglo: Escuchar solo en 127.0.0.1 o filtrar con firewall.

[HIGH    ] sudo sin contraseña para cualquier comando (%kali-trusted) [PRIV-004]
    Quien comprometa esta cuenta es root sin pasos extra.
      - /etc/sudoers.d/kali-grant-root: %kali-trusted ... NOPASSWD: ALL
    Arreglo: Quitar NOPASSWD o limitar los comandos permitidos.
```

> **Note:** this README is in English, but the tool's report output and `--help` are currently in **Spanish**.

## How it works

```
                          the host being audited
                                    |
   +------+----------+------------+---------+---------+--------+----------+
   | ssh  | accounts | filesystem | network | privesc | kernel | services |  ... 12 categories
   +------+----------+------------+---------+---------+--------+----------+
                                    |
                      findings (CRITICAL / HIGH / MEDIUM / LOW / INFO)
                                    |
                   0-100 score + A-F grade (worst finding caps the grade)
                                    |
                        text report, or -f json / -f md
```

Every category is read-only: it inspects config files, running processes and listening sockets on the local
host, it never changes anything and (`--online` aside) never leaves the machine.

## Requirements

- **Linux**, any distro. Some checks need specific tools present (`ss`/`getcap`/`dpkg` or `rpm`...) — a missing one is reported under "skipped checks", not a crash.
- **Python 3.8+**, standard library only. No `pip install` needed to run it.
- **Root is optional.** Without it, checks needing `/etc/shadow`, `sudoers`, the firewall or other users' processes are skipped and the report says so.
- `--online` additionally needs outbound HTTPS to `api.osv.dev` (nothing else is contacted).

## What it checks

| Category | What it looks for |
|---|---|
| `ssh` | `PermitRootLogin`, empty or enabled passwords, `MaxAuthTries`, weak ciphers, host-based auth. Honors `Include` and `Match` the way sshd does, and flags dangerous options re-enabled **inside** `Match` blocks. Also `authorized_keys` permissions, DSA / short RSA keys, weak host keys. Findings are lowered one level when sshd is not listening. |
| `accounts` | Extra UID 0 accounts, empty / MD5 passwords, hashes inside `/etc/passwd`, service accounts with a shell, members of `docker`/`lxd`/`disk` (root-equivalent). |
| `filesystem` | Permissions of `/etc/shadow`, `sudoers` and host keys; a `PATH` with `.` or writable directories (Windows drives in a WSL `PATH` are reported as INFO); world-writable files in `/etc` and systemd units; `/tmp` without `noexec`. |
| `network` | Listeners outside loopback, risky exposed services (Redis, Docker API, Telnet, MongoDB...), missing firewall (ufw/nftables/iptables). |
| `privesc` | **SUID/SGID, capabilities and sudo rules cross-checked against a curated [GTFOBins](https://gtfobins.github.io/)-style list of abusable binaries**; SUID files in `/tmp` or `/home`; reachable Docker socket. |
| `kernel` | ASLR, `kptr_restrict`, `ptrace_scope`, `protected_symlinks`/`hardlinks`/`fifos`/`regular`, `sysrq`, `perf_event_paranoid`, ICMP redirects and broadcasts, SYN cookies, rp_filter... Each one has its own ID (`KER-001`...). |
| `services` | **Anonymous / guest / no-auth access**: Samba guest shares and `map to guest`, anonymous FTP (vsftpd, proftpd, pure-ftpd), NFS exported to `*` or with `no_root_squash`, MongoDB without `authorization`, MySQL `skip-grant-tables` and anonymous users, VNC without a password, guest sessions and autologin (lightdm/GDM/SDDM), default accounts (`kali`, `pi`, `guest`, `test`...), `.rhosts` / `hosts.equiv` / legacy inetd services, default SNMP communities, rsync modules without `auth users`. Also asks local services whether they answer **without credentials** (Redis, Memcached, Elasticsearch, Docker API, Jupyter, etcd, CouchDB, RabbitMQ `guest/guest`). |
| `sensitive` | Private keys, `.pgpass`, `.git-credentials`, `.netrc`, AWS credentials and `.env`/`.npmrc` files **with real secrets inside** that anyone can read; `/etc/shadow` backups; world-writable files and directories outside `/etc` (`/usr/local`, `/opt`, `/srv`, `/var/www`, `/home`); readable home directories on multi-user hosts. |
| `scheduling` | Root cron jobs and root systemd services that run a script or binary other users can modify (or that lives in a writable directory); wildcard injection in `tar`/`chown`/`rsync`; writable `/etc/cron.*`. |
| `policy` | `PASS_MAX_DAYS`, weak `ENCRYPT_METHOD`, PAM `nullok`, missing `pam_pwquality` and account lockout (`pam_faillock`), short `minlen`. |
| `hardening` | AppArmor/SELinux, `core_pattern` piping to a writable program, loaded risky kernel modules (dccp, sctp, rds, tipc, rare filesystems), SSH with passwords and no fail2ban/sshguard/crowdsec. |
| `knownvulns` | Version-based detection for sudo (Baron Samedit, CVE-2025-32463), polkit (PwnKit) and the kernel (Dirty Pipe, Dirty COW). No network needed. |
| `packages` | Pending security updates (apt/dnf), reboot required. With `--online`: CVEs for exposed services and SUID binaries via [OSV.dev](https://osv.dev). |

## Usage

```bash
git clone https://github.com/drplagash/PlagaScan && cd PlagaScan
sudo python3 -m plagascan --all           # EVERYTHING in one command (recommended)
```

`--all` runs **every check** plus the per-package CVE lookup against [OSV.dev](https://osv.dev) (`--online`).
Without `--all` it runs all the local checks and never touches the network. If you installed the package, the command is `sudo plagascan --all`.

Other ways to run it:

```bash
sudo python3 -m plagascan                 # local checks only, no network
python3 -m plagascan -f json -o out.json  # JSON for other tools
python3 -m plagascan -f md -o report.md   # Markdown for documentation
sudo python3 -m plagascan --fail-on high  # exit code 1 on HIGH or worse (CI)
python3 -m plagascan --only privesc --only ssh   # only some categories
python3 -m plagascan --list-checks
```

`--help` groups the options by topic (what to check, output, CI).

It works without root, but skips whatever needs privileges (`/etc/shadow`, `sudoers`, the firewall, other users' processes)
and **says so** in the "skipped checks" section instead of pretending everything is fine.

Optional install as a command: `pip install .` (installs the `plagascan` command).

## Scoring

Every host starts with **100 points** and **each finding subtracts points according to its severity**:

| Severity | Meaning | Examples | Penalty |
|---|---|---|---|
| CRITICAL | Exploitable right now, no effort needed | accounts without a password, Docker socket open to everyone | **−20** |
| HIGH | A clear path to root or a serious exposure | abusable SUID binary, `sudo NOPASSWD: ALL`, root login over SSH | **−10** |
| MEDIUM | Weakens security; another condition is needed to exploit it | SSH password auth, no firewall, pending security updates | **−4** |
| LOW | A missing good practice | `/tmp` without `noexec`, `kptr_restrict` at 0 | **−1** |
| INFO | Informational | list of open ports | 0 |

Points are subtracted **per finding, not per type**: three abusable SUID binaries are three HIGH findings (−30).
The result (minimum 0) maps to a grade:

| Score | 90–100 | 75–89 | 60–74 | 40–59 | 0–39 |
|---|---|---|---|---|---|
| **Grade** | A | B | C | D | F |

### The worst finding sets a ceiling

Subtracting points is not enough: without another rule, a host with a single devastating finding could still earn a good
grade because everything else is in order. So **the worst finding caps the maximum score**:

| If there is at least one... | The score cannot exceed | Best possible grade |
|---|---|---|
| **CRITICAL** | 39 | **F** |
| **HIGH** | 74 | **C** |

The cap only applies when the subtraction-based score is higher; if it was already lower, it stays as it was.
When it kicks in, the report says so: `Puntaje: 39/100  Nota: F  (limitado por hallazgos CRITICAL; por resta serían 80)`
(that is: score 39/100, grade F, capped by CRITICAL findings; subtraction alone would give 80).

| Case | By subtraction | Final score | Grade |
|---|---|---|---|
| No findings | 100 | 100 | A |
| 20 LOW | 80 | 80 | B |
| 5 MEDIUM + 5 LOW | 75 | 75 | B |
| 1 HIGH | 90 | **74** (HIGH cap) | C |
| 4 HIGH | 60 | 60 (already below the cap) | C |
| 1 CRITICAL | 80 | **39** (CRITICAL cap) | F |
| 1 CRITICAL + 1 HIGH | 70 | **39** (CRITICAL cap) | F |

How to read it:
- It is meant to **compare the same host before and after** fixing things: every CRITICAL or HIGH you fix raises the score.
- It is **not meant to compare different hosts**, and it is not a certification.
- The score is always computed from **all** findings, even if you filter the output with `--min-severity`.
- With `-f json` the summary includes `score_before_cap` and `capped_by` so other tools can use them.

## Limitations (read before trusting a report)

- **Read-only.** It never changes anything on the system. Fixes are shown, not applied.
- **Local probes.** To tell whether a service really needs credentials, PlagaScan opens a short connection **to the
  ports this same machine is listening on** and sends one harmless request (`PING`, `GET /`, `version`). It never
  contacts other hosts and never tries passwords, except the well-known RabbitMQ `guest/guest` default on the local console.
- **Config-only findings are lowered a level** when the service is not running, because they only matter if it is started.
- **Version-based detection is a heuristic.** Distributions backport patches without changing the upstream version
  (an Ubuntu `sudo 1.8.31` may already be patched). Those findings say "possible" and need confirming.
- **`--online` sends package names and versions to api.osv.dev** for exposed services and SUID binaries. Nothing else.
  It currently covers Debian and Ubuntu only; OSV also lists advisories that Debian chose not to patch (low priority), so
  "has CVEs" does not always mean "exploitable".
- **SUID/SGID** discovery uses `find -xdev`, so it only covers the root filesystem and does not descend into other mounts.
- The abusable-binaries list is curated and our own. It does not replace GTFOBins: every finding links to the full entry.
- It is not a network vulnerability scanner and does not replace Lynis, OpenSCAP or CIS-CAT. It is a fast, readable review.
- Report output and `--help` are currently in Spanish.

## What has been tested

- **Unit tests:** 114 tests with an in-memory double of the system (they never touch your machine).
  CI runs them on Python 3.8, 3.10 and 3.12.
- **`docs/verify.sh`:** 27 checks on a real Kali (WSL2) host: cross-checks findings against independent commands, plants
  known problems and confirms they are found and then gone.
- **Real services:** Samba guest shares, anonymous FTP (vsftpd), an rsync module without auth and Redis without a
  password were stood up for real (loopback only) and confirmed with `smbclient`, an FTP client, `rsync://` and `redis-cli`.
- **Not yet tested against the real service:** NFS, MongoDB, MySQL/MariaDB and SNMP (covered by unit tests and planted
  configuration files only). Only Kali/Debian-family hosts have been used; Ubuntu, Debian stable and RHEL-family
  (different paths, SELinux) still need a run.

## Not verified yet (as of 2026-10-12)

Be careful with these: they are implemented and unit-tested, but have **not** been confirmed against the real thing.

- **Real services:** NFS, MongoDB, MySQL/MariaDB and SNMP were never run for real (SNMP failed to start under WSL2). The
  probes for Memcached, Elasticsearch, Docker API, Jupyter, etcd, CouchDB and RabbitMQ were only checked against fake
  responses (Elasticsearch also against a fake local server in `verify.sh`).
- **Exposed services:** every real-service test was bound to `127.0.0.1`. The "exposed to the network" severity path is
  covered by unit tests only.
- **Other systems:** only Kali on WSL2 has been used. Ubuntu, Debian stable, RHEL-family (paths, `dnf`, SELinux),
  bare-metal and VMs with systemd-resolved, cron daemons or a real firewall are untested.
- **Several users:** readable home directories, `authorized_keys` permissions, weak keys and default accounts with a real
  `/etc/shadow` were checked with simulated data, not on a host with several real users. The RSA key-size parser was
  validated with synthetic keys, not keys made by `ssh-keygen`.
- **Positive cron / systemd cases:** the real host had no risky cron jobs or services, so those findings were only
  triggered by planted files (cron) and unit tests (systemd `ExecStart`).
- **Online CVE lookup (`--online`):** skipped on Kali (no OSV mapping); not re-run against the OSV API in the latest tests.
- **Scale:** the `find` scans (`/home`, `/opt`, `/srv`, `/var/www`, `/usr/local`) took about 6 s on a small host. On a large
  server they may hit their 90 s limit; that is reported as a skipped check, but it has never been triggered for real.
- **False positives on production servers:** unknown. Several findings reflect distribution defaults (for example PAM
  `nullok`, `PASS_MAX_DAYS 99999`, SSH defaults) and may be noisy on a normal Debian/Ubuntu server.
- **Scoring weights** are a judgment call and have had no independent review; the tool as a whole has not been audited by a third party.

## Not covered yet

PostgreSQL `trust` rules, Grafana default login, Kubernetes/kubelet anonymous access, web-server leaks (directory listing,
`server-status`), mail relays, container audits (privileged containers, published ports), per-account password expiry from
`/etc/shadow`, auditd / time sync / Secure Boot, and comparing two runs. Weak default passwords are **not** tested by logging
in; only the account names are reported.

## Verifying the results

`docs/verify.sh` cross-checks the report against independent commands and **plants known problems** (a 644 `.env` with a
secret, a 777 script run by a root cron job, anonymous FTP, a fake open Redis...) to confirm the scanner finds them and
stops reporting them once removed. Run it as root on a test machine: `sudo bash docs/verify.sh`. It only creates
configuration files that do not already exist and deletes everything it created.

## Real-service lab

`docs/lab/real_up.sh` installs nothing: it configures Samba, vsftpd, rsync, SNMP and Redis (already installed) **insecurely on purpose** and
binds them to `127.0.0.1` only, so you can compare PlagaScan against real clients (`smbclient -N`, an FTP client, `rsync://`,
`redis-cli`). It aborts and stops everything if any of them would listen outside loopback. `docs/lab/real_down.sh` restores
the original configuration. Use it only on a test machine.

## Development

```bash
python3 -m pytest        # tests use a fake context: they never touch your system
sudo bash docs/verify.sh # optional: end-to-end check on a TEST machine (see above)
```

Each check is a function `fn(ctx) -> [Finding]` registered with `@register(...)` in `plagascan/checks/`.
All access to the system goes through `Context`, which the tests replace with an in-memory double.

## Responsible use

Run it only on systems you own or are authorized to assess. The tool exploits nothing, but its report
describes how to escalate privileges on the audited machine, so treat the report as sensitive information.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT

## Author

DrPlaga
