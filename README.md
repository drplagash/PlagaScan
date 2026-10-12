# PlagaScan

![PlagaScan - cover](docs/cover.jpg)

A **read-only, zero-dependency** Linux hardening auditor (Python 3.8+, standard library only).
In seconds it checks the things that most often open the door to a local or remote attacker, and tells you how to fix them.

```
$ sudo plagascan --min-severity medium
Puntaje: 62/100  Nota: C
CRITICAL=0  HIGH=3  MEDIUM=2  LOW=0  INFO=0

[HIGH    ] Binario SUID en una ubicación inusual [PRIV-001]
      - 4755 root /tmp/hatest/find
    Arreglo: Verificar el origen del archivo y quitar el bit: chmod u-s /tmp/hatest/find

[HIGH    ] Capabilities peligrosas en python3 [PRIV-003]
    /tmp/hatest/python3 tiene cap_setuid (cap_setuid: cambiar el UID a 0).
    Ref: https://gtfobins.github.io/gtfobins/python3/

[HIGH    ] sudo sin contraseña para cualquier comando (%kali-trusted) [PRIV-004]
```

> **Note:** this README is in English, but the tool's report output and `--help` are currently in **Spanish**.

## What it checks

| Category | What it looks for |
|---|---|
| `ssh` | `PermitRootLogin`, empty or enabled passwords, `MaxAuthTries`, weak ciphers. Honors `Include` and `Match` the way sshd does. |
| `accounts` | Extra UID 0 accounts, empty / MD5 passwords, hashes inside `/etc/passwd`, service accounts with a shell, members of `docker`/`lxd`/`disk` (root-equivalent). |
| `filesystem` | Permissions of `/etc/shadow`, `sudoers` and host keys; a `PATH` with `.` or writable directories; world-writable files in `/etc` and systemd units; `/tmp` without `noexec`. |
| `network` | Listeners outside loopback, risky exposed services (Redis, Docker API, Telnet, MongoDB...), missing firewall (ufw/nftables/iptables). |
| `privesc` | **SUID/SGID, capabilities and sudo rules cross-checked against a curated [GTFOBins](https://gtfobins.github.io/)-style list of abusable binaries**; SUID files in `/tmp` or `/home`; reachable Docker socket. |
| `kernel` | ASLR, `kptr_restrict`, `ptrace_scope`, `protected_symlinks`, ICMP redirects, SYN cookies, etc. |
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
- **Version-based detection is a heuristic.** Distributions backport patches without changing the upstream version
  (an Ubuntu `sudo 1.8.31` may already be patched). Those findings say "possible" and need confirming.
- **`--online` sends package names and versions to api.osv.dev** for exposed services and SUID binaries. Nothing else.
  It currently covers Debian and Ubuntu only; OSV also lists advisories that Debian chose not to patch (low priority), so
  "has CVEs" does not always mean "exploitable".
- **SUID/SGID** discovery uses `find -xdev`, so it only covers the root filesystem and does not descend into other mounts.
- The abusable-binaries list is curated and our own. It does not replace GTFOBins: every finding links to the full entry.
- It is not a network vulnerability scanner and does not replace Lynis, OpenSCAP or CIS-CAT. It is a fast, readable review.
- Report output and `--help` are currently in Spanish.

## Development

```bash
python3 -m pytest        # tests use a fake context: they never touch your system
```

Each check is a function `fn(ctx) -> [Finding]` registered with `@register(...)` in `plagascan/checks/`.
All access to the system goes through `Context`, which the tests replace with an in-memory double.

## Responsible use

Run it only on systems you own or are authorized to assess. The tool exploits nothing, but its report
describes how to escalate privileges on the audited machine, so treat the report as sensitive information.

## License

MIT

## Author

DrPlaga
