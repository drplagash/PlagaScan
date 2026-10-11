# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
from conftest import FakeContext, ids
from plagascan.checks import ssh, accounts
from plagascan.models import Severity


def test_ssh_first_occurrence_wins_and_match_block_ignored():
    cfg = FakeContext(files={"/etc/ssh/sshd_config": (
        "PermitRootLogin no\nPermitRootLogin yes\n"
        "Match User bob\n  PasswordAuthentication yes\n")})
    parsed = ssh.parse_config(cfg)
    assert parsed["permitrootlogin"] == "no"
    assert "passwordauthentication" not in parsed


def test_ssh_include_is_followed():
    ctx = FakeContext(files={
        "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n",
        "/etc/ssh/sshd_config.d/10.conf": "PasswordAuthentication no\n"})
    assert ssh.parse_config(ctx)["passwordauthentication"] == "no"


def test_ssh_flags_dangerous_settings():
    ctx = FakeContext(files={"/etc/ssh/sshd_config": (
        "PermitRootLogin yes\nPermitEmptyPasswords yes\nMaxAuthTries 10\n"
        "Ciphers aes128-cbc,aes256-gcm@openssh.com\n")})
    found = ids(ssh.check_ssh(ctx))
    assert {"SSH-001", "SSH-002", "SSH-003", "SSH-005", "SSH-008"} <= set(found)


def test_ssh_hardened_config_is_clean_except_defaults():
    ctx = FakeContext(files={"/etc/ssh/sshd_config": (
        "PermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\n")})
    assert ssh.check_ssh(ctx) == []


def test_ssh_missing_config_is_skipped_not_crashed():
    ctx = FakeContext()
    assert ssh.check_ssh(ctx) == []
    assert ctx.skipped


PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "toor:x:0:0:backdoor:/root:/bin/bash\n"
          "www-data:x:33:33:www:/var/www:/bin/bash\n"
          "alice:x:1000:1000::/home/alice:/bin/bash\n")


def test_accounts_uid0_and_service_shell():
    ctx = FakeContext(files={"/etc/passwd": PASSWD, "/etc/group": "docker:x:998:alice\n"})
    found = accounts.check_accounts(ctx)
    by_id = {f.id: f for f in found}
    assert by_id["ACC-001"].severity == Severity.CRITICAL
    assert by_id["ACC-001"].evidence == ["toor"]
    assert "www-data" in by_id["ACC-005"].evidence
    assert by_id["ACC-006"].evidence == ["alice"]


def test_accounts_empty_and_md5_passwords():
    ctx = FakeContext(files={
        "/etc/passwd": PASSWD,
        "/etc/shadow": "alice::19000:0:99999:7:::\nbob:$1$abc$hash:19000::::::\nroot:$y$j9T$x:1::::::\n"})
    by_id = {f.id: f for f in accounts.check_accounts(ctx)}
    assert by_id["ACC-003"].evidence == ["alice"]
    assert by_id["ACC-004"].evidence == ["bob"]


def test_accounts_shadow_unreadable_records_skip():
    ctx = FakeContext(files={"/etc/passwd": PASSWD}, root=False)
    accounts.check_accounts(ctx)
    assert any("shadow" in c for c, _ in ctx.skipped)
