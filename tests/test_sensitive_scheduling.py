# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
from conftest import FakeContext, ids
from plagascan.checks import hardening, policy, scheduling, sensitive
from plagascan.models import Severity


def by_id(findings, fid):
    return [f for f in findings if f.id == fid]


# --- sensitive ----------------------------------------------------------------------------

def secrets_cmd(ctx_roots):
    return " ".join(sensitive._find_secrets_cmd(ctx_roots))


def test_world_readable_private_key_and_env_with_secret():
    roots = ["/home", "/root", "/etc"]
    find = secrets_cmd(roots)
    out = "644 ana /home/ana/.ssh/id_ed25519\n644 ana /home/ana/app/.env\n644 ana /home/ana/tpl/.npmrc\n"
    ctx = FakeContext(
        stats={r: (0o755, 0, 0) for r in roots},
        files={"/home/ana/app/.env": "API_" + "KEY=" + "k" * 12 + "\n", "/home/ana/tpl/.npmrc": "registry=https://x\n"},
        commands={find: out})
    found = by_id(sensitive.check_sensitive(ctx), "SEC-001")
    paths = " ".join(f.evidence[0] for f in found)
    assert "id_ed25519" in paths and "app/.env" in paths
    assert ".npmrc" not in paths  # plantilla sin secreto
    assert [f for f in found if "id_ed25519" in f.evidence[0]][0].severity == Severity.HIGH


def test_secret_content_detection():
    fake = "k7" * 3 + "9q" * 4  # valor falso armado en tiempo de ejecución
    assert sensitive.has_secret_content("DB_" + "PASSWORD=" + fake)
    assert sensitive.has_secret_content("//registry.npmjs.org/:_auth" + "Token=" + fake)
    assert not sensitive.has_secret_content("PASSWORD=${DB_PASS}\nTOKEN=changeme\nUID=1000")
    assert not sensitive.has_secret_content("registry=https://registry.npmjs.org/")


def test_shadow_backup_permissions():
    ctx = FakeContext(stats={"/etc/shadow-": (0o644, 0, 0), "/etc/passwd-": (0o644, 0, 0)})
    out = by_id(sensitive.check_sensitive(ctx), "SEC-002")
    assert len(out) == 1 and out[0].severity == Severity.HIGH


def test_world_writable_files_and_dirs_outside_etc():
    roots = ["/usr/local", "/opt", "/home"]
    base = "find " + " ".join(roots) + " -xdev -type %s -perm -0002 %s-printf %%m %%u %%p\\n"
    ctx = FakeContext(
        stats={r: (0o755, 0, 0) for r in roots},
        commands={base % ("f", ""): "777 root /usr/local/bin/backup.sh\n666 ana /home/ana/x\n",
                  base % ("d", "! -perm -1000 "): "777 root /opt/shared\n"})
    out = sensitive.check_sensitive(ctx)
    files = by_id(out, "SEC-003")
    assert sorted(f.severity for f in files) == [Severity.LOW, Severity.HIGH]
    assert by_id(out, "SEC-004")[0].severity == Severity.LOW  # /opt: MEDIUM menos un nivel


def test_homes_readable_only_with_several_users():
    passwd = "a:x:1000:1000::/home/a:/bin/bash\nb:x:1001:1001::/home/b:/bin/bash\n"
    ctx = FakeContext(files={"/etc/passwd": passwd},
                      stats={"/home/a": (0o755, 1000, 1000), "/home/b": (0o750, 1001, 1001)})
    (f,) = by_id(sensitive.check_sensitive(ctx), "SEC-005")
    assert f.evidence == ["0755 /home/a"]
    one = FakeContext(files={"/etc/passwd": "a:x:1000:1000::/home/a:/bin/bash\n"},
                      stats={"/home/a": (0o755, 1000, 1000)})
    assert not by_id(sensitive.check_sensitive(one), "SEC-005")


# --- scheduling --------------------------------------------------------------------------------

def test_parse_crontab_system_and_user_formats():
    sysjobs = scheduling.parse_crontab("SHELL=/bin/sh\n17 * * * * root /opt/run.sh\n@reboot bob /x\n", system=True)
    assert sysjobs[0] == {"user": "root", "cmd": "/opt/run.sh"} and sysjobs[1]["user"] == "bob"
    ujobs = scheduling.parse_crontab("*/5 * * * * /home/a/job.sh\n", system=False, default_user="a")
    assert ujobs == [{"user": "a", "cmd": "/home/a/job.sh"}]


def test_root_cron_runs_world_writable_script():
    ctx = FakeContext(
        files={"/etc/crontab": "* * * * * root /opt/run.sh\n* * * * * ana /home/ana/x.sh\n"},
        stats={"/opt/run.sh": (0o777, 0, 0), "/opt": (0o755, 0, 0), "/home/ana/x.sh": (0o777, 1000, 1000)})
    (f,) = by_id(scheduling.check_scheduling(ctx), "SCH-001")
    assert f.severity == Severity.HIGH and "/opt/run.sh" in f.evidence[0]
    assert "/home/ana" not in " ".join(f.evidence)  # el cron de ana no es de root


def test_root_cron_script_owned_by_user_or_in_writable_dir():
    ctx = FakeContext(
        files={"/etc/cron.d/j": "* * * * * root /srv/a.sh\n* * * * * root /srv2/b.sh\n"},
        stats={"/srv/a.sh": (0o755, 1000, 1000), "/srv2/b.sh": (0o755, 0, 0), "/srv2": (0o777, 0, 0)})
    (f,) = by_id(scheduling.check_scheduling(ctx), "SCH-001")
    assert len(f.evidence) == 2


def test_root_cron_safe_script_no_finding():
    ctx = FakeContext(files={"/etc/crontab": "* * * * * root /usr/local/bin/ok.sh\n"},
                      stats={"/usr/local/bin/ok.sh": (0o755, 0, 0), "/usr/local/bin": (0o755, 0, 0)})
    assert ids(scheduling.check_scheduling(ctx)) == []


def test_cron_wildcard_injection():
    ctx = FakeContext(files={"/etc/crontab": "0 3 * * * root cd /srv/data && tar czf /bk/a.tgz *\n"})
    assert by_id(scheduling.check_scheduling(ctx), "SCH-002")


def test_cron_directory_writable():
    ctx = FakeContext(stats={"/etc/cron.daily": (0o777, 0, 0)})
    assert by_id(scheduling.check_scheduling(ctx), "SCH-003")


def test_systemd_service_exec_writable_but_user_services_skipped():
    root_unit = "[Service]\nExecStart=/opt/app/run --x\n"
    user_unit = "[Service]\nUser=ana\nExecStart=/opt/other/run\n"
    ctx = FakeContext(
        files={"/etc/systemd/system/a.service": root_unit, "/etc/systemd/system/b.service": user_unit},
        stats={"/opt/app/run": (0o775, 0, 1000), "/opt/other/run": (0o777, 0, 0), "/opt/app": (0o755, 0, 0)})
    (f,) = by_id(scheduling.check_scheduling(ctx), "SCH-004")
    assert "a.service" in f.evidence[0] and len(f.evidence) == 1


def test_wsl_mnt_paths_ignored_in_scheduling():
    ctx = FakeContext(files={"/proc/version": "Linux microsoft-standard-WSL2",
                             "/etc/crontab": "* * * * * root /mnt/c/x.sh\n"},
                      stats={"/mnt/c/x.sh": (0o777, 1000, 1000)})
    assert ids(scheduling.check_scheduling(ctx)) == []


# --- policy -------------------------------------------------------------------------------------

PAM_WEAK = {"/etc/pam.d/common-auth": "auth [success=1] pam_unix.so nullok\n",
            "/etc/pam.d/common-password": "password [success=1] pam_unix.so obscure yescrypt\n"}


def test_policy_findings():
    ctx = FakeContext(files=dict(PAM_WEAK, **{
        "/etc/login.defs": "PASS_MAX_DAYS 99999\nENCRYPT_METHOD MD5\n",
        "/etc/security/pwquality.conf": "minlen = 6\n"}))
    got = ids(policy.check_policy(ctx))
    for fid in ("POL-001", "POL-002", "POL-003", "POL-004", "POL-005", "POL-006"):
        assert fid in got
    assert by_id(policy.check_policy(ctx), "POL-002")[0].severity == Severity.HIGH


def test_policy_good_config_is_clean():
    ctx = FakeContext(files={
        "/etc/login.defs": "PASS_MAX_DAYS 90\nENCRYPT_METHOD YESCRYPT\n",
        "/etc/pam.d/common-auth": "auth required pam_faillock.so deny=5\nauth [success=1] pam_unix.so\n",
        "/etc/pam.d/common-password": "password requisite pam_pwquality.so retry=3\n",
        "/etc/security/pwquality.conf": "minlen = 12\n"})
    assert ids(policy.check_policy(ctx)) == []


# --- hardening ---------------------------------------------------------------------------------------

def test_no_mac_is_info_on_wsl_low_elsewhere():
    wsl = FakeContext(files={"/proc/version": "Linux ... microsoft ..."})
    assert by_id(hardening.check_hardening(wsl), "HARD-001")[0].severity == Severity.INFO
    real = FakeContext(files={"/proc/version": "Linux 6.1"})
    assert by_id(hardening.check_hardening(real), "HARD-001")[0].severity == Severity.LOW
    ok = FakeContext(files={"/sys/module/apparmor/parameters/enabled": "Y\n"})
    assert not by_id(hardening.check_hardening(ok), "HARD-001")


def test_core_pattern_pipe_to_writable_program():
    ctx = FakeContext(files={"/proc/sys/kernel/core_pattern": "|/tmp/handler %p\n"},
                      stats={"/tmp/handler": (0o777, 1000, 1000)})
    assert by_id(hardening.check_hardening(ctx), "HARD-002")[0].severity == Severity.HIGH
    safe = FakeContext(files={"/proc/sys/kernel/core_pattern": "|/usr/share/apport/apport %p\n"},
                       stats={"/usr/share/apport/apport": (0o755, 0, 0)})
    assert not by_id(hardening.check_hardening(safe), "HARD-002")


def test_risky_modules_loaded():
    ctx = FakeContext(files={"/proc/modules": "sctp 100 0 - Live 0x0\next4 1 1 - Live 0x0\n"})
    (f,) = by_id(hardening.check_hardening(ctx), "HARD-003")
    assert "sctp" in f.evidence[0]


def test_fail2ban_missing_when_ssh_exposed_with_passwords():
    ss = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
    ctx = FakeContext(commands={"ss -H -tulnp": ss, "ss -H -tln": ss}, files={"/etc/ssh/sshd_config": "\n"})
    assert by_id(hardening.check_hardening(ctx), "HARD-004")
    guarded = FakeContext(commands={"ss -H -tulnp": ss, "ss -H -tln": ss, "systemctl is-active fail2ban": "active\n"},
                          files={"/etc/ssh/sshd_config": "\n"})
    assert not by_id(hardening.check_hardening(guarded), "HARD-004")
