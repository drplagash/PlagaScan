# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""MAC (AppArmor/SELinux), core_pattern, módulos de kernel de riesgo y fail2ban."""
from typing import List

from . import register
from .common import is_wsl, listening
from ..models import Finding, Severity
from .ssh import effective_config

CAT = "hardening"

RISKY_MODULES = {
    "dccp": "protocolo DCCP (CVEs históricos, casi sin uso)",
    "sctp": "protocolo SCTP (superficie de ataque, casi sin uso)",
    "rds": "protocolo RDS (CVEs históricos)",
    "tipc": "protocolo TIPC (CVEs históricos)",
    "cramfs": "sistema de archivos cramfs", "freevxfs": "sistema de archivos freevxfs",
    "hfs": "sistema de archivos hfs", "hfsplus": "sistema de archivos hfsplus",
    "jffs2": "sistema de archivos jffs2", "udf": "sistema de archivos udf",
}


def _check_mac(ctx) -> List[Finding]:
    apparmor = (ctx.read("/sys/module/apparmor/parameters/enabled") or "").strip().upper() == "Y"
    selinux = (ctx.read("/sys/fs/selinux/enforce") or "").strip()
    if apparmor or selinux == "1":
        return []
    ev = []
    if selinux == "0":
        ev.append("SELinux presente pero en modo permissive")
    ev.append("AppArmor no está activo" if not apparmor else "")
    wsl = is_wsl(ctx)
    return [Finding(
        "HARD-001", "Sin control de acceso obligatorio (AppArmor/SELinux)",
        Severity.INFO if wsl else Severity.LOW, CAT,
        "Un servicio comprometido no queda confinado." + (" WSL no trae AppArmor/SELinux en su kernel." if wsl else ""),
        "Activar AppArmor (apt install apparmor) o SELinux en modo enforcing.", [e for e in ev if e])]


def _check_core_pattern(ctx) -> List[Finding]:
    pat = (ctx.read("/proc/sys/kernel/core_pattern") or "").strip()
    if not pat.startswith("|"):
        return []
    target = pat[1:].split()[0] if pat[1:].split() else ""
    if not target.startswith("/"):
        return []
    st = ctx.stat(target)
    if st and (st[0] & 0o002 or st[1] != 0):
        return [Finding("HARD-002", "core_pattern entrega los core dumps a un programa modificable",
                        Severity.HIGH, CAT,
                        "El kernel ejecuta ese programa como root cuando un proceso se cierra con core dump.",
                        "Dejar el programa root:root sin escritura para otros.",
                        ["%s (modo %04o, uid %d)" % (target, st[0], st[1])])]
    return []


def _check_modules(ctx) -> List[Finding]:
    text = ctx.read("/proc/modules")
    if not text:
        return []
    loaded = {l.split()[0] for l in text.splitlines() if l.split()}
    ev = ["%s: %s" % (m, why) for m, why in RISKY_MODULES.items() if m in loaded]
    if not ev:
        return []
    return [Finding("HARD-003", "Módulos de kernel de riesgo cargados", Severity.LOW, CAT,
                    "Cada módulo cargado es superficie de ataque del kernel y estos casi nunca se usan.",
                    "Bloquear con 'install <modulo> /bin/false' en /etc/modprobe.d/.", ev)]


def _check_fail2ban(ctx) -> List[Finding]:
    if not listening(ctx, 22):
        return []
    cfg, _src = effective_config(ctx)
    if cfg.get("passwordauthentication", "yes").lower() != "yes":
        return []
    for unit in ("fail2ban", "sshguard", "crowdsec"):
        out = ctx.run(["systemctl", "is-active", unit])
        if out and out.strip() == "active":
            return []
    return [Finding("HARD-004", "SSH con contraseñas y sin fail2ban/sshguard/crowdsec", Severity.LOW, CAT,
                    "Nada frena la fuerza bruta contra SSH.",
                    "Instalar fail2ban o pasar a autenticación solo por clave.",
                    ["sshd escucha en 22, PasswordAuthentication yes, ningún servicio de bloqueo activo"])]


@register(CAT, "MAC, core dumps, módulos de riesgo y protección contra fuerza bruta")
def check_hardening(ctx) -> List[Finding]:
    return _check_mac(ctx) + _check_core_pattern(ctx) + _check_modules(ctx) + _check_fail2ban(ctx)
