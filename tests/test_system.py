# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
from conftest import FakeContext, ids
from plagascan.checks import network, kernel, knownvulns, filesystem
from plagascan.models import Severity

SS = """\
tcp   LISTEN 0 128  0.0.0.0:22     0.0.0.0:*  users:(("sshd",pid=811,fd=3))
tcp   LISTEN 0 511  127.0.0.1:631  0.0.0.0:*  users:(("cupsd",pid=900,fd=7))
tcp   LISTEN 0 511  *:6379         *:*        users:(("redis-server",pid=1200,fd=6))
tcp   LISTEN 0 4096 [::]:2375      [::]:*     users:(("dockerd",pid=1300,fd=9))
udp   UNCONN 0 0    0.0.0.0%lo:53  0.0.0.0:*  users:(("systemd-resolve",pid=500,fd=13))
tcp   LISTEN 0 128  [::1]:5432     [::]:*
"""


def test_parse_ss_handles_ipv6_zone_and_missing_process():
    rows = network.parse_ss(SS)
    assert len(rows) == 6
    by_port = {r["port"]: r for r in rows}
    assert by_port[22]["process"] == "sshd" and by_port[22]["pid"] == 811
    assert by_port[2375]["host"] == "::"
    assert by_port[53]["host"] == "0.0.0.0"
    assert by_port[5432]["process"] == ""


def test_exposure_logic():
    assert network.is_exposed("0.0.0.0") and network.is_exposed("*") and network.is_exposed("192.168.1.5")
    assert not network.is_exposed("127.0.0.1") and not network.is_exposed("::1")


def test_risky_ports_only_when_exposed():
    ctx = FakeContext(commands={"ss -H -tulnp": SS})
    found = network.check_network(ctx)
    risky = {f.title.split(" expuesto")[0]: f.severity for f in found if f.id == "NET-002"}
    assert risky["Redis"] == Severity.HIGH
    assert risky["Docker API sin TLS"] == Severity.CRITICAL
    assert "PostgreSQL" not in risky           # solo en loopback
    assert ctx.shared["listeners"]


def test_firewall_missing_vs_present():
    empty = FakeContext(commands={"ss -H -tulnp": "", "iptables -S": "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n"})
    assert "NET-003" in ids(network.check_network(empty))
    ok = FakeContext(commands={"ss -H -tulnp": "", "ufw status": "Status: active\n"})
    assert "NET-003" not in ids(network.check_network(ok))
    unknown = FakeContext(commands={"ss -H -tulnp": ""}, root=False)
    assert "NET-003" not in ids(network.check_network(unknown))
    assert any("firewall" in c for c, _ in unknown.skipped)


def test_kernel_sysctl():
    ctx = FakeContext(files={
        "/proc/sys/kernel/randomize_va_space": "0\n",
        "/proc/sys/kernel/kptr_restrict": "2\n",
        "/proc/sys/fs/protected_symlinks": "1\n"})
    found = kernel.check_kernel(ctx)
    assert [f.title for f in found] == ["ASLR no está completo"]


def test_kernel_without_proc_is_skipped():
    ctx = FakeContext()
    assert kernel.check_kernel(ctx) == []
    assert ctx.skipped


def test_version_parsing_and_ranges():
    p = knownvulns.parse_version
    assert p("1.9.5p2") == (1, 9, 5, 2)
    assert p("5.15.0-91-generic") == (5, 15, 0, 91)
    assert knownvulns.in_range(p("1.9.5p1"), (1, 9, 0), (1, 9, 5, 2))
    assert not knownvulns.in_range(p("1.9.5p2"), (1, 9, 0), (1, 9, 5, 2))


def test_sudo_baron_samedit_detected_and_patched_version_clean():
    vuln = FakeContext(commands={"sudo -V": "Sudo version 1.8.31\nSudoers policy plugin\n"})
    assert "KV-001" in ids(knownvulns.check_known(vuln))
    fixed = FakeContext(commands={"sudo -V": "Sudo version 1.9.5p2\n"})
    assert "KV-001" not in ids(knownvulns.check_known(fixed))


def test_sudo_chroot_cve_2025():
    assert "KV-002" in ids(knownvulns.check_known(FakeContext(commands={"sudo -V": "Sudo version 1.9.16p2\n"})))
    assert "KV-002" not in ids(knownvulns.check_known(FakeContext(commands={"sudo -V": "Sudo version 1.9.17p1\n"})))


def test_dirty_pipe_and_dirty_cow_ranges():
    dp = knownvulns.check_known(FakeContext(commands={"uname -r": "5.10.50-generic\n"}))
    assert "KV-004" in ids(dp)
    safe = knownvulns.check_known(FakeContext(commands={"uname -r": "6.1.0-18-amd64\n"}))
    assert safe == []
    assert "KV-005" in ids(knownvulns.check_known(FakeContext(commands={"uname -r": "3.10.0-1160.el7\n"})))


def test_filesystem_permissions_and_path():
    ctx = FakeContext(
        stats={"/etc/shadow": (0o644, 0, 0), "/etc/passwd": (0o666, 0, 0), "/etc/group": (0o644, 0, 0),
               "/usr/local/bin": (0o777, 0, 0)},
        env={"PATH": "/usr/bin::/usr/local/bin"},
        commands={"find /etc -xdev -type f -perm -0002": "/etc/cron.d/oops\n"})
    found = filesystem.check_filesystem(ctx)
    sev = {f.title: f.severity for f in found}
    assert sev["Permisos excesivos en /etc/passwd"] == Severity.CRITICAL   # world-writable
    assert sev["Permisos excesivos en /etc/shadow"] == Severity.HIGH
    assert "Permisos excesivos en /etc/group" not in sev
    assert "FS-002" in ids(found) and "FS-003" in ids(found)
