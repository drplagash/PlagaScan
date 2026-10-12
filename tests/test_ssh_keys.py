# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
import base64
import struct

from conftest import FakeContext, ids
from plagascan.checks import ssh
from plagascan.models import Severity


def rsa_line(bits):
    def mpint(n):
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return struct.pack(">I", len(raw)) + raw
    blob = struct.pack(">I", 7) + b"ssh-rsa" + mpint(65537) + mpint((1 << (bits - 1)) | 12345)
    return "ssh-rsa " + base64.b64encode(blob).decode() + " user@host"


def test_key_strength_measures_rsa_bits():
    assert ssh.key_strength(rsa_line(1024)) == ("ssh-rsa", 1024)
    assert ssh.key_strength(rsa_line(2048)) == ("ssh-rsa", 2048)
    assert ssh.key_strength(rsa_line(4096))[1] == 4096
    assert ssh.key_strength('command="x",no-pty ' + rsa_line(1024))[1] == 1024
    assert ssh.key_strength("ssh-ed25519 AAAAC3Nz user")[0] == "ssh-ed25519"
    assert ssh.key_strength("# comentario") is None


def test_weak_and_loose_authorized_keys():
    path = "/home/a/.ssh/authorized_keys"
    ctx = FakeContext(
        files={path: rsa_line(1024) + "\nssh-dss AAAAB3Nza user\n" + rsa_line(4096) + "\n"},
        stats={path: (0o666, 1000, 1000), "/home/a/.ssh": (0o700, 1000, 1000)})
    out = {f.id: f for f in ssh.check_ssh_keys(ctx)}
    assert out["SSH-011"].severity == Severity.HIGH
    assert len(out["SSH-012"].evidence) == 2  # DSA + RSA 1024; la de 4096 no


def test_strong_keys_with_good_permissions_are_clean():
    path = "/root/.ssh/authorized_keys"
    ctx = FakeContext(files={path: rsa_line(3072) + "\n"},
                      stats={path: (0o600, 0, 0), "/root/.ssh": (0o700, 0, 0)})
    assert ids(ssh.check_ssh_keys(ctx)) == []


def test_match_block_reopens_dangerous_option():
    cfg = "PermitRootLogin no\nMatch User deploy\n  PermitEmptyPasswords yes\nMatch Address 10.0.0.0/8\n  PermitRootLogin yes\n"
    out = ssh.check_ssh_keys(FakeContext(files={"/etc/ssh/sshd_config": cfg}))
    (f,) = [x for x in out if x.id == "SSH-010"]
    assert f.severity == Severity.CRITICAL and len(f.evidence) == 2


def test_match_overrides_follow_includes():
    ctx = FakeContext(files={"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n",
                             "/etc/ssh/sshd_config.d/a.conf": "Match User x\n PermitRootLogin yes\n"})
    assert len(ssh.match_overrides(ctx)) == 1


def test_hostbased_and_rhosts_in_global_config():
    cfg = "HostbasedAuthentication yes\nIgnoreRhosts no\n"
    out = ssh.check_ssh(FakeContext(files={"/etc/ssh/sshd_config": cfg}, root=False))
    (f,) = [x for x in out if x.id == "SSH-009"]
    assert len(f.evidence) == 2


def test_weak_host_keys():
    ctx = FakeContext(files={"/etc/ssh/ssh_host_dsa_key": "x", "/etc/ssh/ssh_host_rsa_key.pub": "x"},
                      commands={"ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub": "1024 SHA256:abc root@h (RSA)\n"})
    (f,) = [x for x in ssh.check_ssh_keys(ctx) if x.id == "SSH-013"]
    assert len(f.evidence) == 2
