# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Políticas de contraseñas: login.defs, PAM y bloqueo por intentos fallidos."""
import re
from typing import List

from . import register
from .common import active_lines, is_wsl, parse_kv
from ..models import Finding, Severity

CAT = "policy"

PAM_FILES = ("/etc/pam.d/common-auth", "/etc/pam.d/common-password", "/etc/pam.d/system-auth",
             "/etc/pam.d/password-auth", "/etc/pam.d/sshd", "/etc/pam.d/login")


def _pam_lines(ctx):
    for path in PAM_FILES:
        text = ctx.read(path)
        if text is not None:
            for line in active_lines(text, ("#",)):
                yield path, line


@register(CAT, "Política de contraseñas, PAM y bloqueo por intentos")
def check_policy(ctx) -> List[Finding]:
    out: List[Finding] = []

    defs = parse_kv(ctx.read("/etc/login.defs"), sep=" ")
    if defs:
        try:
            days = int(defs.get("pass_max_days", "99999"))
        except ValueError:
            days = 99999
        if days > 365:
            out.append(Finding(
                "POL-001", "Las contraseñas nuevas no vencen (PASS_MAX_DAYS=%d)" % days, Severity.LOW, CAT,
                "Una contraseña filtrada sirve para siempre si nadie la rota.",
                "Poner PASS_MAX_DAYS 365 (o menos) en /etc/login.defs.", ["PASS_MAX_DAYS %d" % days]))
        method = defs.get("encrypt_method", "").upper()
        if method in ("DES", "MD5"):
            out.append(Finding(
                "POL-002", "ENCRYPT_METHOD débil (%s)" % method, Severity.HIGH, CAT,
                "Los hashes nuevos se generan con un algoritmo roto: se descifran en segundos.",
                "Usar ENCRYPT_METHOD YESCRYPT (o SHA512).", ["ENCRYPT_METHOD %s" % method]))

    pam = list(_pam_lines(ctx))
    if pam:
        nullok = ["%s: %s" % (p, l[:80]) for p, l in pam if re.search(r"\bnullok\b", l) and l.startswith("auth")]
        if nullok:
            out.append(Finding(
                "POL-003", "PAM acepta contraseñas vacías (nullok)", Severity.LOW, CAT,
                "Una cuenta con contraseña vacía puede autenticarse.",
                "Quitar 'nullok' de las líneas pam_unix.", nullok))
        text_all = "\n".join(l for _p, l in pam)
        has_quality = "pam_pwquality" in text_all or "pam_cracklib" in text_all
        if any("common-password" in p or "system-auth" in p or "password-auth" in p for p, _ in pam) and not has_quality:
            out.append(Finding(
                "POL-004", "Sin control de calidad de contraseñas (pam_pwquality)", Severity.LOW, CAT,
                "Se aceptan contraseñas triviales.",
                "Instalar libpam-pwquality y configurar minlen/dcredit en /etc/security/pwquality.conf.",
                ["pam_pwquality/pam_cracklib no está en la pila de contraseñas"]))
        if not any(k in text_all for k in ("pam_faillock", "pam_tally2", "pam_tally")):
            # En WSL o sin servicios de red el riesgo práctico es bajo.
            sev = Severity.INFO if is_wsl(ctx) else Severity.LOW
            out.append(Finding(
                "POL-005", "Sin bloqueo de cuenta por intentos fallidos (faillock)", sev, CAT,
                "Los intentos de adivinar contraseñas no se frenan a nivel PAM.",
                "Agregar pam_faillock (deny=5 unlock_time=900) o usar fail2ban.",
                ["no hay pam_faillock/pam_tally2 en la pila de autenticación"]))

    pw = parse_kv(ctx.read("/etc/security/pwquality.conf"))
    try:
        if "minlen" in pw and int(pw["minlen"]) < 8:
            out.append(Finding("POL-006", "Largo mínimo de contraseña menor a 8", Severity.LOW, CAT,
                               "Contraseñas muy cortas se adivinan por fuerza bruta.",
                               "Poner minlen = 12 en /etc/security/pwquality.conf.", ["minlen = %s" % pw["minlen"]]))
    except ValueError:
        pass
    return out
