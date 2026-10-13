# Changelog

## 0.4.2 - 2026-10-12
- Documentation: refreshed README (current sample output, what has and has not been tested, what is not covered yet),
  English package description, this changelog, and an explicit "Not verified yet" section listing what has not been
  confirmed against real systems.

## 0.4.1 - 2026-10-12
- Config-based service findings (Samba, FTP, NFS, MongoDB, MySQL, SNMP, rsync) drop one level and say so when the service
  listens only on loopback, not just when it is stopped. Found by testing against real services.
- `map to guest` has its own explanation.
- Add `docs/lab/real_up.sh` / `real_down.sh` (insecure-on-purpose services bound to 127.0.0.1, automatic abort and revert).

## 0.4.0 - 2026-10-12
- New categories: `services` (anonymous/guest/no-auth access, local no-credentials probes, default accounts, guest
  sessions), `sensitive` (readable secrets, shadow backups, world-writable files), `scheduling` (root cron/systemd running
  modifiable files), `policy` (login.defs, PAM) and `hardening` (AppArmor/SELinux, core_pattern, risky modules, fail2ban).
- SSH: `Match` overrides, `authorized_keys` permissions and weak keys, weak host keys, host-based auth.
- Kernel: `sysrq`, `perf_event_paranoid`, `protected_fifos`/`regular`, ICMP broadcast.
- `docs/verify.sh` now plants known problems and checks they are found and then gone.

## 0.3.3 - 2026-10-12
- Windows drives in a WSL `PATH` are reported as INFO (`FS-007`) instead of an insecure `PATH`.

## 0.3.2 - 2026-10-12
- Unique kernel finding IDs (`KER-001`...`KER-013`).
- SSH: values that come from OpenSSH defaults are labelled as such; findings are lowered one level when sshd is not listening.

## 0.3.1 - 2026-10-12
- Fix update counts that did not match the evidence list, detect VNC on 5901-5909, count IPv4+IPv6 listeners once,
  show the "try sudo" hint only when not root, clearer OSV skip message. Add `docs/verify.sh`.

## 0.3.0 and earlier - 2026-10-11
- Initial release (0.1.0), rename to PlagaScan, scoring with caps by worst finding, `--all`, grouped `--help`, English README.
