# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Utilidades compartidas por los checks de servicios, secretos y políticas."""
import re
from typing import Dict, Iterable, List, Optional

from ..models import Severity
from .network import is_exposed, parse_ss

TRUE = ("yes", "true", "1", "on", "enabled")


def truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in TRUE


def listeners(ctx) -> List[Dict]:
    """Puertos en escucha (se calculan una sola vez y se comparten)."""
    if "listeners" not in ctx.shared:
        text = ctx.run(["ss", "-H", "-tulnp"])
        ctx.shared["listeners"] = parse_ss(text) if text else []
    return ctx.shared["listeners"]  # type: ignore[return-value]


def listening(ctx, port: int) -> bool:
    return any(l["port"] == port for l in listeners(ctx))


def exposed_on(ctx, port: int) -> bool:
    """True si el puerto escucha fuera de loopback."""
    return any(l["port"] == port and is_exposed(l["host"]) for l in listeners(ctx))


def probe_host(ctx, port: int) -> str:
    """Dirección local (de este equipo) para probar un puerto en escucha."""
    for l in listeners(ctx):
        if l["port"] == port:
            h = l["host"]
            return "127.0.0.1" if h in ("*", "0.0.0.0", "::", "") else h
    return "127.0.0.1"


def is_wsl(ctx) -> bool:
    return "microsoft" in (ctx.read("/proc/version") or "").lower()


def lower(sev: Severity, steps: int = 1) -> Severity:
    return Severity(max(int(sev) - steps, int(Severity.INFO)))


def reach(ctx, *ports: int) -> str:
    """'exposed' (escucha fuera de loopback), 'local' (solo 127.0.0.1/::1) o 'off' (no escucha)."""
    hit = [l for l in listeners(ctx) if l["port"] in ports]
    if not hit:
        return "off"
    return "exposed" if any(is_exposed(l["host"]) for l in hit) else "local"


def adjust(sev: Severity, state):
    """Baja un nivel si el servicio no escucha o solo escucha en loopback; devuelve (sev, nota).

    `state` es el resultado de reach(); un bool se acepta por compatibilidad (True = expuesto).
    """
    if isinstance(state, bool):
        state = "exposed" if state else "off"
    if state == "exposed" or sev == Severity.INFO:
        return sev, ""
    if state == "local":
        return lower(sev), " El servicio escucha solo en loopback: no es alcanzable desde la red."
    return lower(sev), " El servicio no está escuchando: aplica solo si se activa."


def active_lines(text: Optional[str], comment: Iterable[str] = ("#", ";")) -> List[str]:
    """Líneas no vacías y sin comentarios (y sin comentarios al final)."""
    out = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line[0] in tuple(comment):
            continue
        out.append(line)
    return out


def parse_ini(text: Optional[str], default_section: str = "global") -> Dict[str, Dict[str, str]]:
    """INI estilo smb.conf/rsyncd.conf: claves en minúscula y con espacios normalizados."""
    sections: Dict[str, Dict[str, str]] = {default_section: {}}
    cur = default_section
    for line in active_lines(text):
        m = re.match(r"^\[(.+)\]$", line)
        if m:
            cur = m.group(1).strip().lower()
            sections.setdefault(cur, {})
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            k = re.sub(r"[\s_]+", " ", k.strip().lower())
            sections[cur][k] = v.strip().strip('"').lower()
    return sections


def parse_kv(text: Optional[str], sep: str = "=") -> Dict[str, str]:
    """Líneas `clave=valor` (vsftpd, mysql, login.defs con sep=' ')."""
    cfg: Dict[str, str] = {}
    for line in active_lines(text):
        if sep == " ":
            parts = line.split(None, 1)
            if len(parts) == 2:
                cfg[parts[0].lower()] = parts[1].strip()
        elif sep in line:
            k, _, v = line.partition(sep)
            cfg[k.strip().lower()] = v.strip()
    return cfg
