# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Configuración efectiva de sshd."""
from typing import Dict, List, Optional

from . import register
from ..models import Finding, Severity

CAT = "ssh"

DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "x11forwarding": "no",
    "maxauthtries": "6",
    "allowagentforwarding": "yes",
    "allowtcpforwarding": "yes",
    "permituserenvironment": "no",
    "port": "22",
    "protocol": "2",
}

WEAK_ALGOS = ("3des", "arcfour", "blowfish", "cast128", "-cbc", "hmac-md5",
              "hmac-sha1-96", "diffie-hellman-group1", "diffie-hellman-group14-sha1")


def parse_config(ctx, path: str = "/etc/ssh/sshd_config", _depth: int = 0) -> Dict[str, str]:
    """Parsea sshd_config con la semántica de sshd: gana la primera aparición.

    Se detiene en el primer bloque `Match` (solo importa la sección global)
    y sigue las directivas `Include`.
    """
    cfg: Dict[str, str] = {}
    text = ctx.read(path)
    if text is None or _depth > 5:
        return cfg
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if key == "match":
            break
        if key == "include":
            for pattern in value.split():
                if not pattern.startswith("/"):
                    pattern = "/etc/ssh/" + pattern
                for inc in ctx.glob(pattern):
                    for k, v in parse_config(ctx, inc, _depth + 1).items():
                        cfg.setdefault(k, v)
            continue
        cfg.setdefault(key, value.strip('"'))
    return cfg


def effective_config(ctx):
    """Prefiere `sshd -T` (valores reales); si no, parsea el archivo."""
    out = ctx.run(["sshd", "-T"]) if ctx.is_root else None
    if out:
        cfg = {}
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                cfg.setdefault(parts[0].lower(), parts[1].strip())
        return cfg, "sshd -T"
    cfg = parse_config(ctx)
    return cfg, "sshd_config"


def _sshd_listening(ctx, cfg: Dict[str, str]):
    """True/False si sshd escucha en su puerto; None si no se puede saber."""
    text = ctx.run(["ss", "-H", "-tln"])
    if not text:
        return None
    port = (cfg.get("port") or DEFAULTS["port"]).split()[0]
    return any(l.split()[3:4] and l.split()[3].rsplit(":", 1)[-1] == port
               for l in text.splitlines())


def _src(cfg: Dict[str, str], key: str, source: str) -> str:
    return source if key in cfg else "valor por defecto de OpenSSH"


def _get(cfg: Dict[str, str], key: str) -> str:
    return cfg.get(key, DEFAULTS.get(key, "")).lower()


@register(CAT, "Configuración de SSH")
def check_ssh(ctx) -> List[Finding]:
    out: List[Finding] = []
    cfg, source = effective_config(ctx)
    if not cfg:
        ctx.skip(CAT, "no se pudo leer la configuración de sshd")
        return out

    active = _sshd_listening(ctx, cfg)
    inactive = active is False
    note = " sshd no está escuchando: solo aplica si se activa el servicio." if inactive else ""

    def sev(base: Severity) -> Severity:
        return Severity(max(base - 1, Severity.INFO)) if inactive and base < Severity.CRITICAL else base

    root = _get(cfg, "permitrootlogin")
    if root == "yes":
        out.append(Finding(
            "SSH-001", "Login de root por SSH habilitado", Severity.HIGH, CAT,
            "PermitRootLogin yes permite ataques de fuerza bruta directos contra root.",
            "Usar PermitRootLogin no (o prohibit-password) y entrar con un usuario normal + sudo.",
            ["PermitRootLogin %s (%s)" % (root, source)]))

    if _get(cfg, "passwordauthentication") == "yes":
        out.append(Finding(
            "SSH-002", "Autenticación por contraseña habilitada", sev(Severity.MEDIUM), CAT,
            "Con contraseñas activas el servicio es blanco de fuerza bruta y credential stuffing." + note,
            "Usar claves públicas y poner PasswordAuthentication no.",
            ["PasswordAuthentication %s (%s)" % (
                _get(cfg, "passwordauthentication"), _src(cfg, "passwordauthentication", source))]))

    if _get(cfg, "permitemptypasswords") == "yes":
        out.append(Finding(
            "SSH-003", "SSH permite contraseñas vacías", Severity.CRITICAL, CAT,
            "Cualquier cuenta sin contraseña puede entrar por red.",
            "Poner PermitEmptyPasswords no.", ["PermitEmptyPasswords yes"]))

    if _get(cfg, "permituserenvironment") == "yes":
        out.append(Finding(
            "SSH-004", "PermitUserEnvironment habilitado", Severity.MEDIUM, CAT,
            "Permite que los usuarios inyecten variables (LD_PRELOAD) que pueden saltar restricciones.",
            "Poner PermitUserEnvironment no.", ["PermitUserEnvironment yes"]))

    try:
        tries = int(_get(cfg, "maxauthtries") or 6)
    except ValueError:
        tries = 6
    if tries > 4:
        out.append(Finding(
            "SSH-005", "MaxAuthTries alto", sev(Severity.LOW), CAT,
            "Más intentos por conexión facilita la fuerza bruta." + note,
            "Usar MaxAuthTries 3 o 4.",
            ["MaxAuthTries %d (%s)" % (tries, _src(cfg, "maxauthtries", source))]))

    if _get(cfg, "x11forwarding") == "yes":
        out.append(Finding(
            "SSH-006", "X11Forwarding habilitado", sev(Severity.LOW), CAT,
            "Amplía la superficie de ataque hacia el cliente y el servidor X." + note,
            "Poner X11Forwarding no si no se usa.",
            ["X11Forwarding yes (%s)" % _src(cfg, "x11forwarding", source)]))

    if _get(cfg, "protocol") == "1":
        out.append(Finding(
            "SSH-007", "Protocolo SSH 1 habilitado", Severity.CRITICAL, CAT,
            "El protocolo 1 está roto criptográficamente.", "Usar solo Protocol 2.",
            ["Protocol 1"]))

    weak = []
    for key in ("ciphers", "macs", "kexalgorithms"):
        val = cfg.get(key, "").lower()
        weak += ["%s: %s" % (key, a) for a in WEAK_ALGOS if a in val]
    if weak:
        out.append(Finding(
            "SSH-008", "Algoritmos criptográficos débiles permitidos", Severity.MEDIUM, CAT,
            "Hay cifrados/MACs/KEX obsoletos habilitados.",
            "Restringir Ciphers, MACs y KexAlgorithms a los modernos (chacha20, aes-gcm, curve25519).",
            weak[:8]))
    return out
