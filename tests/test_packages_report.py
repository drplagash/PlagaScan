import json

from conftest import FakeContext, ids
from hardenaudit import cli
from hardenaudit.checks import packages
from hardenaudit.models import Finding, Severity, grade, score
from hardenaudit.report import render_json, render_markdown, render_text

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


def test_score_and_grade():
    fs = [Finding("A", "t", Severity.CRITICAL, "c"), Finding("B", "t", Severity.HIGH, "c"),
          Finding("C", "t", Severity.INFO, "c")]
    assert score(fs) == 70 and grade(70) == "C"
    assert score([]) == 100 and grade(100) == "A"
    assert score(fs * 10) == 0 and grade(0) == "F"


def test_renderers_roundtrip():
    fs = [Finding("X-1", "Algo grave", Severity.HIGH, "ssh", "detalle", "arreglo", ["ev1"], ["http://r"])]
    data = json.loads(render_json(fs, [("ssh", "porque sí")]))
    assert data["summary"]["score"] == 90
    assert data["findings"][0]["severity"] == "HIGH"
    assert data["skipped"][0]["reason"] == "porque sí"
    assert "Algo grave" in render_text(fs, [], color=False)
    assert "\033[" in render_text(fs, [], color=True)
    assert "## [HIGH] Algo grave" in render_markdown(fs, [])


def test_cli_runs_checks_and_one_broken_check_does_not_abort(monkeypatch):
    from hardenaudit import checks
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
