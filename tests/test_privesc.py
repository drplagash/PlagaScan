# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
from conftest import FakeContext, ids
from plagascan.checks import privesc
from plagascan.models import Severity

FIND_CMD = ('find / -xdev -type f ( -perm -4000 -o -perm -2000 ) -not -path /proc/* '
            '-printf %m %u %p\\n')


def suid_ctx(listing, **kw):
    return FakeContext(commands={FIND_CMD: listing, "getcap -r": ""}, **kw)


def test_expected_suid_binaries_are_not_flagged():
    ctx = suid_ctx("4755 root /usr/bin/sudo\n4755 root /usr/bin/passwd\n4755 root /usr/bin/mount\n")
    assert privesc._check_suid(ctx) == []
    assert ctx.shared["suid_paths"] == ["/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/mount"]


def test_abusable_suid_is_flagged_with_gtfobins_reference():
    ctx = suid_ctx("4755 root /usr/bin/find\n")
    (f,) = privesc._check_suid(ctx)
    assert f.id == "PRIV-002" and f.severity == Severity.HIGH
    assert f.references == ["https://gtfobins.github.io/gtfobins/find/"]


def test_suid_not_owned_by_root_is_medium():
    (f,) = privesc._check_suid(suid_ctx("4755 backup /usr/local/bin/python3\n"))
    assert f.severity == Severity.MEDIUM


def test_suid_in_tmp_is_flagged_whatever_the_binary():
    (f,) = privesc._check_suid(suid_ctx("4755 root /tmp/.x/harmless\n"))
    assert f.id == "PRIV-001"


def test_sgid_alone_is_not_flagged():
    assert privesc._check_suid(suid_ctx("2755 root /usr/bin/find\n")) == []


def test_getcap_parsing_both_formats():
    rows = dict(privesc.parse_getcap(
        "/usr/bin/ping cap_net_raw=ep\n/tmp/py cap_setuid,cap_chown+ep\n/x = cap_dac_override=ep\n"))
    assert rows["/usr/bin/ping"] == ["cap_net_raw"]
    assert rows["/tmp/py"] == ["cap_chown", "cap_setuid"]
    assert rows["/x"] == ["cap_dac_override"]


def test_dangerous_capability_on_interpreter_is_high():
    ctx = FakeContext(commands={"getcap -r": "/opt/py/python3 cap_setuid=ep\n/usr/bin/ping cap_net_raw=ep\n"},
                      stats={"/opt": (0o755, 0, 0)})
    ctx.stats["/usr"] = (0o755, 0, 0)
    # getcap recibe las raíces existentes, así que el comando fake las incluye
    ctx.commands["getcap -r /usr /opt"] = ctx.commands.pop("getcap -r")
    found = privesc._check_caps(ctx)
    assert ids(found) == ["PRIV-003"] and found[0].severity == Severity.HIGH


SUDOERS = """\
Defaults env_reset
User_Alias ADMINS = alice
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
alice ALL=(root) NOPASSWD: /usr/bin/vim, /usr/bin/systemctl restart nginx
bob ALL=(ALL) NOPASSWD: ALL
carol ALL=(root) /usr/bin/less
dave ALL=(root) /usr/bin/backup *
"""


def test_parse_sudoers_keeps_nopasswd_across_commands():
    rules = privesc.parse_sudoers(SUDOERS)
    vim = next(r for r in rules if r["cmd"] == "/usr/bin/vim")
    ctl = next(r for r in rules if r["cmd"].startswith("/usr/bin/systemctl"))
    less = next(r for r in rules if r["cmd"] == "/usr/bin/less")
    assert vim["nopasswd"] and ctl["nopasswd"] and not less["nopasswd"]
    assert all(r["who"] != "Defaults" for r in rules)


def test_sudoers_findings():
    ctx = FakeContext(files={"/etc/sudoers": SUDOERS})
    found = {(f.id, f.severity) for f in privesc._check_sudoers(ctx)}
    assert ("PRIV-004", Severity.HIGH) in found          # bob NOPASSWD: ALL
    assert ("PRIV-005", Severity.HIGH) in found          # alice vim sin password
    assert ("PRIV-005", Severity.MEDIUM) in found        # carol less con password
    assert ("PRIV-006", Severity.MEDIUM) in found        # dave con comodín


def test_default_sudo_group_is_not_flagged():
    ctx = FakeContext(files={"/etc/sudoers": "%sudo ALL=(ALL:ALL) ALL\nroot ALL=(ALL) ALL\n"})
    assert privesc._check_sudoers(ctx) == []


def test_sudoers_unreadable_is_skipped():
    ctx = FakeContext(root=False)
    assert privesc._check_sudoers(ctx) == []
    assert ctx.skipped


def test_docker_socket_world_accessible():
    ctx = FakeContext(stats={"/var/run/docker.sock": (0o666, 0, 0)})
    (f,) = privesc._check_docker_sock(ctx)
    assert f.severity == Severity.CRITICAL
    assert privesc._check_docker_sock(FakeContext(stats={"/var/run/docker.sock": (0o660, 0, 0)})) == []
