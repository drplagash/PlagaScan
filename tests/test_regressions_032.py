# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
from conftest import FakeContext
from plagascan.checks import kernel, ssh
from plagascan.models import Severity

CFG = {"/etc/ssh/sshd_config": "X11Forwarding yes\n"}


def _by_id(findings):
    return {f.id: f for f in findings}


def test_kernel_ids_are_unique():
    files = {"/proc/sys/" + p: "0\n" for p, *_ in kernel.SYSCTLS}
    out = kernel.check_kernel(FakeContext(files=files))
    ids = [f.id for f in out]
    assert len(ids) > 3 and len(ids) == len(set(ids))


def test_ssh_defaults_are_labelled_and_inactive_sshd_lowers_severity():
    ctx = FakeContext(files=CFG, root=False, commands={"ss -H -tln": "LISTEN 0 5 0.0.0.0:5901 0.0.0.0:*\n"})
    f = _by_id(ssh.check_ssh(ctx))
    assert "valor por defecto" in f["SSH-002"].evidence[0]
    assert "X11Forwarding yes (sshd_config)" in f["SSH-006"].evidence[0]
    assert f["SSH-002"].severity == Severity.LOW
    assert "no está escuchando" in f["SSH-002"].detail


def test_ssh_active_keeps_severity():
    ctx = FakeContext(files=CFG, root=False, commands={"ss -H -tln": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"})
    assert _by_id(ssh.check_ssh(ctx))["SSH-002"].severity == Severity.MEDIUM


def test_ssh_unknown_listening_state_keeps_severity():
    assert _by_id(ssh.check_ssh(FakeContext(files=CFG, root=False)))["SSH-002"].severity == Severity.MEDIUM
