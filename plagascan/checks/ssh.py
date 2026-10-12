# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Configuración efectiva de sshd."""
import base64
import re
import struct
from typing import Dict, List, Optional, Tuple

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
    "hostbasedauthentication": "no",
    "ignorerhosts": "yes",
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


@register(CAT, "Configuración y claves de SSH")
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

    if _get(cfg, "hostbasedauthentication") == "yes" or _get(cfg, "ignorerhosts") == "no":
        ev = []
        if _get(cfg, "hostbasedauthentication") == "yes":
            ev.append("HostbasedAuthentication yes")
        if _get(cfg, "ignorerhosts") == "no":
            ev.append("IgnoreRhosts no")
        out.append(Finding(
            "SSH-009", "SSH confía en hosts (HostbasedAuthentication / .rhosts)", sev(Severity.MEDIUM), CAT,
            "Se puede entrar sin contraseña desde otro equipo que figure como confiable." + note,
            "Poner HostbasedAuthentication no e IgnoreRhosts yes.", ev))

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


# --- claves y excepciones dentro de bloques Match ------------------------------------------------

RISKY_MATCH = {
    "permitemptypasswords": ("yes", Severity.CRITICAL),
    "permitrootlogin": ("yes", Severity.HIGH),
    "hostbasedauthentication": ("yes", Severity.MEDIUM),
}


def match_overrides(ctx, path: str = "/etc/ssh/sshd_config", _depth: int = 0) -> List[Tuple[str, str, str]]:
    """[(condición Match, directiva, valor)] de las directivas peligrosas dentro de bloques Match."""
    text = ctx.read(path)
    if text is None or _depth > 5:
        return []
    found: List[Tuple[str, str, str]] = []
    cond = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key, value = parts[0].lower(), (parts[1].strip() if len(parts) > 1 else "")
        if key == "match":
            cond = value
        elif key == "include":
            for pattern in value.split():
                pattern = pattern if pattern.startswith("/") else "/etc/ssh/" + pattern
                for inc in ctx.glob(pattern):
                    found.extend(match_overrides(ctx, inc, _depth + 1))
        elif cond and key in RISKY_MATCH and value.lower() == RISKY_MATCH[key][0]:
            found.append((cond, parts[0], value))
    return found


_KEY_RE = re.compile(r"(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-\S+|sk-\S+)\s+([A-Za-z0-9+/=]+)")


def key_strength(line: str) -> Optional[Tuple[str, int]]:
    """(tipo, bits) de una línea de authorized_keys; bits=0 si no aplica o no se pudo leer."""
    m = _KEY_RE.search(line)
    if not m:
        return None
    ktype = m.group(1)
    if ktype != "ssh-rsa":
        return ktype, 0
    try:
        blob = base64.b64decode(m.group(2))
        pos, parts = 0, []
        for _ in range(3):
            (n,) = struct.unpack(">I", blob[pos:pos + 4])
            parts.append(blob[pos + 4:pos + 4 + n])
            pos += 4 + n
        modulus = parts[2].lstrip(b"\x00")
        if not modulus:
            return ktype, 0
        return ktype, (len(modulus) - 1) * 8 + modulus[0].bit_length()
    except (ValueError, struct.error, IndexError):
        return ktype, 0


@register(CAT, "Configuración y claves de SSH")
def check_ssh_keys(ctx) -> List[Finding]:
    out: List[Finding] = []

    ov = match_overrides(ctx)
    if ov:
        sev = max(RISKY_MATCH[k.lower()][1] for _c, k, _v in ov)
        out.append(Finding(
            "SSH-010", "Bloque Match de sshd reabre una opción peligrosa", sev, CAT,
            "Aunque la configuración global sea segura, estos usuarios/hosts quedan exceptuados.",
            "Quitar la directiva del bloque Match o justificarla.",
            ["Match %s: %s %s" % (c, k, v) for c, k, v in ov]))

    perm, weak = [], []
    for path in ctx.glob("/home/*/.ssh/authorized_keys") + ctx.glob("/root/.ssh/authorized_keys"):
        st = ctx.stat(path)
        if st and st[0] & 0o022:
            perm.append("%04o %s" % (st[0], path))
        sdir = ctx.stat(path.rsplit("/", 1)[0])
        if sdir and sdir[0] & 0o022:
            perm.append("%04o %s" % (sdir[0], path.rsplit("/", 1)[0]))
        for n, line in enumerate((ctx.read(path) or "").splitlines(), 1):
            ks = key_strength(line)
            if not ks:
                continue
            if ks[0] == "ssh-dss":
                weak.append("%s:%d clave DSA (obsoleta, 1024 bits)" % (path, n))
            elif ks[0] == "ssh-rsa" and 0 < ks[1] < 2048:
                weak.append("%s:%d clave RSA de %d bits" % (path, n, ks[1]))
    if perm:
        out.append(Finding(
            "SSH-011", "authorized_keys o ~/.ssh escribibles por grupo/otros", Severity.HIGH, CAT,
            "Otro usuario puede agregar su clave y entrar como esa cuenta.",
            "chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys", perm))
    if weak:
        out.append(Finding(
            "SSH-012", "Claves SSH autorizadas débiles", Severity.HIGH, CAT,
            "Las claves DSA y las RSA de menos de 2048 bits son factorizables o están deprecadas.",
            "Reemplazar por ed25519 (ssh-keygen -t ed25519).", weak))

    hk = []
    if ctx.exists("/etc/ssh/ssh_host_dsa_key"):
        hk.append("/etc/ssh/ssh_host_dsa_key (DSA, obsoleta)")
    pub = "/etc/ssh/ssh_host_rsa_key.pub"
    if ctx.exists(pub):
        info = ctx.run(["ssh-keygen", "-l", "-f", pub])
        if info and info.split() and info.split()[0].isdigit() and int(info.split()[0]) < 2048:
            hk.append("%s (RSA de %s bits)" % (pub, info.split()[0]))
    if hk:
        out.append(Finding(
            "SSH-013", "Claves de host SSH débiles", Severity.MEDIUM, CAT,
            "Una clave de host débil permite suplantar el servidor.",
            "Borrar la clave DSA y regenerar la RSA con 4096 bits (o usar solo ed25519).", hk))
    return out
