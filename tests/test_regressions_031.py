# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
from conftest import FakeContext
from plagascan.checks import network, packages
from plagascan.models import Severity
from plagascan.report import render_text

SS = (
    "tcp LISTEN 0 128 0.0.0.0:5901 0.0.0.0:* users:((\"Xtigervnc\",pid=1,fd=5))\n"
    "tcp LISTEN 0 128 [::]:5901 [::]:* users:((\"Xtigervnc\",pid=1,fd=6))\n"
)


def test_vnc_5901_is_flagged_and_ipv4_ipv6_count_once():
    ctx = FakeContext(commands={"ss -H -tulnp": SS})
    out = network.check_network(ctx)
    n001 = [f for f in out if f.id == "NET-001"][0]
    assert n001.title.startswith("1 ")
    n002 = [f for f in out if f.id == "NET-002"]
    assert n002 and n002[0].severity == Severity.HIGH


def test_pending_updates_keep_full_evidence():
    lines = "\n".join(
        "pkg%d/stable 2.0 amd64 [upgradable from: 1.0]" % i for i in range(18))
    ctx = FakeContext(
        files={"/etc/os-release": "ID=kali\nID_LIKE=debian\n"},
        commands={"apt list --upgradable": "Listing...\n" + lines})
    out = packages.check_packages(ctx)
    f = [x for x in out if x.id in ("PKG-001", "PKG-002")][0]
    assert str(len(f.evidence)) in f.title


def test_sudo_hint_only_when_not_root(monkeypatch):
    import os
    skipped = [("x", "y")]
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert "sudo" not in render_text([], skipped, False).split("Checks omitidos")[1].split("\n")[0]
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    assert "sudo" in render_text([], skipped, False).split("Checks omitidos")[1].split("\n")[0]
