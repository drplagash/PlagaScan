# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
import json

from conftest import FakeContext, ids
from plagascan import cli
from plagascan.checks import packages
from plagascan.models import Finding, Severity, grade, score, score_detail
from plagascan.report import render_json, render_markdown, render_text

APT = """\
Listing...
openssl/stable-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.11-1~deb12u2]
curl/stable-security 7.88.1-10+deb12u8 amd64 [upgradable from: 7.88.1-10+deb12u5]
vim/stable 2:9.0.1378-2+deb12u2 amd64 [upgradable from: 2:9.0.1378-2]
"""

# Aviso real de Debian (recortado): CVEs en `upstream`, varias releases en `affected`.
DSA = {
    "id": "DSA-5586-1",
    "upstream": ["CVE-2023-48795", "DEBIAN-CVE-2023-48795", "CVE-2023-51385"],
    "affected": [
        {"package": {"name": "openssh", "ecosystem": "Debian:11"},
         "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1:8.4p1-5+deb11u3"}]}]},
        {"package": {"name": "openssh", "ecosystem": "Debian:12"},
         "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1:9.2p1-2+deb12u2"}]}]},
    ],
}


def test_parse_apt_marks_security_updates():
    rows = packages.parse_apt_upgradable(APT)
    assert [(r["name"], r["security"]) for r in rows] == [
        ("openssl", True), ("curl", True), ("vim", False)]


def test_pending_updates_findings():
    ctx = FakeContext(files={"/etc/os-release": 'ID=debian\nVERSION_ID="12"\n',
                             "/var/run/reboot-required": ""},
                      commands={"apt list --upgradable": APT})
    found = {f.id: f for f in packages.check_packages(ctx)}
    assert found["PKG-001"].severity == Severity.MEDIUM and len(found["PKG-001"].evidence) == 2
    assert "PKG-002" in found and "PKG-003" in found


def test_extract_vuln_filters_by_ecosystem_and_ignores_debian_prefix():
    cves, fixed = packages.extract_vuln(DSA, "DSA-5586-1", "openssh", "Debian:12")
    assert cves == ["CVE-2023-48795", "CVE-2023-51385"]
    assert fixed == ["1:9.2p1-2+deb12u2"]          # no mezcla la de Debian 11


def test_extract_vuln_falls_back_to_advisory_id():
    cves, fixed = packages.extract_vuln({}, "DLA-1-1", "x", "Debian:12")
    assert cves == ["DLA-1-1"] and fixed == []


def test_osv_ecosystem_mapping():
    f = packages.osv_ecosystem
    assert f({"ID": "debian", "VERSION_ID": "12"}) == "Debian:12"
    assert f({"ID": "ubuntu", "VERSION_ID": "22.04"}) == "Ubuntu:22.04:LTS"
    assert f({"ID": "ubuntu", "VERSION_ID": "23.10"}) == "Ubuntu:23.10"
    assert f({"ID": "kali", "VERSION_ID": "2026.3"}) is None


def test_online_flow_with_mocked_osv(monkeypatch):
    calls = []

    def fake_http(url, body=None, timeout=20):
        calls.append(url)
        if url == packages.OSV_BATCH:
            return {"results": [{"vulns": [{"id": "DSA-5586-1"}]}]}
        return DSA

    monkeypatch.setattr(packages, "_http_json", fake_http)
    ctx = FakeContext(
        online=True,
        files={"/etc/os-release": 'ID=debian\nVERSION_ID="12"\n'},
        commands={"apt list --upgradable": "Listing...\n", "which sshd": "/usr/sbin/sshd\n",
                  "readlink -f /usr/sbin/sshd": "/usr/sbin/sshd\n",
                  "dpkg -S /usr/sbin/sshd": "openssh-server: /usr/sbin/sshd\n",
                  "dpkg-query -W -f=${source:Package}\t${source:Version}\n openssh-server":
                      "openssh\t1:9.2p1-2\n"})
    ctx.shared["listeners"] = [{"host": "0.0.0.0", "port": 22, "process": "sshd", "proto": "tcp", "pid": 1}]
    (f,) = [x for x in packages.check_packages(ctx) if x.id == "PKG-010"]
    assert f.evidence == ["CVE-2023-48795", "CVE-2023-51385"]
    assert "1:9.2p1-2+deb12u2" in f.remediation and "sshd:22" in f.detail


def test_online_network_failure_is_skipped_not_fatal(monkeypatch):
    monkeypatch.setattr(packages, "_http_json", lambda *a, **k: None)
    ctx = FakeContext(online=True, files={"/etc/os-release": "ID=debian\nVERSION_ID=12\n"},
                      commands={"apt list --upgradable": "", "which sshd": "/usr/sbin/sshd\n",
                                "dpkg -S /usr/sbin/sshd": "openssh-server: /usr/sbin/sshd\n",
                                "dpkg-query -W -f=${source:Package}\t${source:Version}\n openssh-server":
                                    "openssh\t1:9.2p1-2\n"})
    ctx.shared["listeners"] = [{"host": "0.0.0.0", "port": 22, "process": "sshd", "proto": "tcp", "pid": 1}]
    assert [f for f in packages.check_packages(ctx) if f.id == "PKG-010"] == []
    assert any("osv" in c for c, _ in ctx.skipped)


def fs_of(*severities):
    return [Finding("X", "t", s, "c") for s in severities]


def test_score_without_serious_findings_is_plain_subtraction():
    assert score([]) == 100 and grade(100) == "A"
    assert score(fs_of(Severity.INFO, Severity.INFO)) == 100
    assert score(fs_of(Severity.MEDIUM, Severity.MEDIUM, Severity.LOW)) == 91
    assert score_detail(fs_of(Severity.MEDIUM)) == (96, 96, None)
    # 10 MEDIUM: 60 por resta, sin HIGH ni CRITICAL, no hay techo
    assert score(fs_of(*[Severity.MEDIUM] * 10)) == 60


def test_a_single_high_can_no_longer_give_an_A():
    pts, raw, cap = score_detail(fs_of(Severity.HIGH))
    assert (pts, raw, cap) == (74, 90, "HIGH")
    assert grade(pts) == "C"
    # con muchos LOW + 1 HIGH, tampoco pasa de C
    assert score(fs_of(Severity.HIGH, *[Severity.LOW] * 3)) == 74


def test_a_single_critical_means_F():
    pts, raw, cap = score_detail(fs_of(Severity.CRITICAL))
    assert (pts, raw, cap) == (39, 80, "CRITICAL")
    assert grade(pts) == "F"
    # el techo de CRITICAL manda aunque haya HIGH
    assert score(fs_of(Severity.CRITICAL, Severity.HIGH)) == 39


def test_cap_never_raises_a_score_that_is_already_lower():
    fs = fs_of(*[Severity.CRITICAL] * 5)            # 0 por resta
    assert score_detail(fs) == (0, 0, None)
    assert score(fs_of(*[Severity.HIGH] * 4)) == 60  # 60 < 74: manda la resta
    assert score(fs_of(Severity.CRITICAL, Severity.HIGH) * 10) == 0
    assert grade(0) == "F"


def test_summary_is_computed_over_all_findings_not_only_the_shown_ones():
    all_f = fs_of(Severity.CRITICAL, Severity.LOW)
    shown = fs_of(Severity.LOW)                     # --min-severity dejó afuera el CRITICAL
    data = json.loads(render_json(shown, [], all_f))
    assert data["summary"]["score"] == 39 and data["summary"]["capped_by"] == "CRITICAL"
    assert "limitado por hallazgos CRITICAL" in render_text(shown, [], False, all_f)
    assert "limitado por hallazgos CRITICAL" in render_markdown(shown, [], all_f)
    plain = json.loads(render_json(shown, []))      # sin all_findings: usa lo que recibe
    assert plain["summary"]["score"] == 99 and plain["summary"]["capped_by"] is None


def test_renderers_roundtrip():
    fs = [Finding("X-1", "Algo grave", Severity.HIGH, "ssh", "detalle", "arreglo", ["ev1"], ["http://r"])]
    data = json.loads(render_json(fs, [("ssh", "porque sí")]))
    assert data["summary"]["score"] == 74 and data["summary"]["score_before_cap"] == 90
    assert data["findings"][0]["severity"] == "HIGH"
    assert data["skipped"][0]["reason"] == "porque sí"
    assert "Algo grave" in render_text(fs, [], color=False)
    assert "\033[" in render_text(fs, [], color=True)
    assert "## [HIGH] Algo grave" in render_markdown(fs, [])


def test_cli_runs_checks_and_one_broken_check_does_not_abort(monkeypatch):
    from plagascan import checks
    checks.load_all()

    def boom(ctx):
        raise RuntimeError("fallo simulado")

    monkeypatch.setattr(checks, "REGISTRY", [("roto", "x", boom)] + checks.REGISTRY[:1])
    monkeypatch.setattr(cli, "REGISTRY", checks.REGISTRY)
    ctx = FakeContext()
    cli.run_checks(ctx)
    assert any(c == "roto" and "fallo simulado" in r for c, r in ctx.skipped)


def test_cli_exit_codes(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "platform", "linux")
    assert cli.main(["--list-checks"]) == 0
    assert "privesc" in capsys.readouterr().out
    assert cli.main(["--min-severity", "nope", "--force"]) == 2


def test_all_flag_turns_on_online_checks_and_default_stays_offline(monkeypatch):
    seen = []

    def fake_run_checks(ctx, only=None, skip=None):
        seen.append((ctx.online, only))
        return []

    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "run_checks", fake_run_checks)
    assert cli.main([]) == 0 and seen[-1] == (False, None)          # por defecto: sin red
    assert cli.main(["--online"]) == 0 and seen[-1][0] is True
    assert cli.main(["--all"]) == 0 and seen[-1][0] is True
    assert cli.main(["-a", "--only", "ssh"]) == 0 and seen[-1] == (True, ["ssh"])   # --only sigue valiendo


def test_help_is_grouped_and_mentions_all(capsys):
    try:
        cli.main(["--help"])
    except SystemExit:
        pass
    out = capsys.readouterr().out
    assert "qué revisar" in out and "salida" in out and "integración (CI)" in out
    assert "--all" in out and "ejemplos:" in out
