# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Puertos en escucha y firewall."""
import re
from typing import Dict, List, Optional

from . import register
from ..models import Finding, Severity

CAT = "network"

# puerto -> (servicio, severidad si está expuesto a la red, consejo)
RISKY_PORTS = {
    21: ("FTP", Severity.MEDIUM, "FTP envía credenciales en claro; usar SFTP."),
    23: ("Telnet", Severity.HIGH, "Telnet no cifra nada; reemplazar por SSH."),
    69: ("TFTP", Severity.MEDIUM, "TFTP no autentica."),
    111: ("rpcbind", Severity.LOW, "Solo necesario con NFS."),
    139: ("SMB/NetBIOS", Severity.MEDIUM, "Exponer SMB a la red amplía mucho el riesgo."),
    445: ("SMB", Severity.MEDIUM, "Exponer SMB a la red amplía mucho el riesgo."),
    161: ("SNMP", Severity.MEDIUM, "Comunidades por defecto (public) filtran información."),
    873: ("rsync", Severity.MEDIUM, "Suele estar sin autenticación."),
    2049: ("NFS", Severity.MEDIUM, "Revisar exports y root_squash."),
    2375: ("Docker API sin TLS", Severity.CRITICAL, "Equivale a root remoto sin autenticación."),
    3306: ("MySQL/MariaDB", Severity.MEDIUM, "Bases de datos no deberían escuchar en todas las interfaces."),
    5432: ("PostgreSQL", Severity.MEDIUM, "Bases de datos no deberían escuchar en todas las interfaces."),
    5900: ("VNC", Severity.HIGH, "VNC suele tener autenticación débil."),
    **{p: ("VNC", Severity.HIGH, "VNC suele tener autenticación débil.") for p in range(5901, 5910)},
    6379: ("Redis", Severity.HIGH, "Redis sin autenticación permite ejecución de comandos."),
    9200: ("Elasticsearch", Severity.HIGH, "Sin autenticación por defecto en versiones antiguas."),
    11211: ("Memcached", Severity.HIGH, "Sin autenticación; usado en ataques de amplificación."),
    27017: ("MongoDB", Severity.HIGH, "Sin autenticación en configuraciones por defecto antiguas."),
}

_PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')


def parse_ss(text: str) -> List[Dict]:
    """Parsea `ss -H -tulnp` a una lista de listeners."""
    rows = []
    for line in text.splitlines():
        f = line.split(None, 6)
        if len(f) < 5:
            continue
        proto, local = f[0], f[4]
        host, _, port = local.rpartition(":")
        host = host.split("%")[0].strip("[]")
        if not port.isdigit():
            continue
        m = _PROC_RE.search(f[6]) if len(f) > 6 else None
        rows.append({
            "proto": proto, "host": host, "port": int(port),
            "process": m.group(1) if m else "", "pid": int(m.group(2)) if m else 0,
        })
    return rows


def is_exposed(host: str) -> bool:
    if host in ("*", "0.0.0.0", "::", ""):
        return True
    if host.startswith("127.") or host == "::1":
        return False
    return True


@register(CAT, "Puertos en escucha y firewall")
def check_network(ctx) -> List[Finding]:
    out: List[Finding] = []
    text = ctx.run(["ss", "-H", "-tulnp"])
    if text is None:
        ctx.skip(CAT, "no se encontró el comando 'ss' (paquete iproute2)")
        listeners: List[Dict] = []
    else:
        listeners = parse_ss(text)
        ctx.shared["listeners"] = listeners
        if not ctx.is_root and any(not l["process"] for l in listeners):
            ctx.skip(CAT + "/procesos", "sin root no se ven los procesos de otros usuarios")

    exposed = [l for l in listeners if is_exposed(l["host"])]
    if exposed:
        ev = ["%s %s:%d %s" % (l["proto"], l["host"], l["port"], l["process"] or "-")
              for l in exposed]
        n_ports = len({(l["proto"][:3], l["port"]) for l in exposed})  # IPv4+IPv6 = un puerto
        out.append(Finding(
            "NET-001", "%d puertos escuchan fuera de loopback" % n_ports, Severity.INFO,
            CAT, "Cada servicio expuesto es superficie de ataque.",
            "Cerrar o limitar con firewall lo que no sea necesario.", ev[:30]))

    seen = set()
    for l in exposed:
        info = RISKY_PORTS.get(l["port"])
        if info and (l["port"], l["proto"]) not in seen:
            seen.add((l["port"], l["proto"]))
            name, sev, advice = info
            out.append(Finding(
                "NET-002", "%s expuesto en %s/%d" % (name, l["proto"], l["port"]), sev, CAT,
                advice, "Escuchar solo en 127.0.0.1 o filtrar con firewall.",
                ["%s:%d %s" % (l["host"], l["port"], l["process"] or "-")]))

    out.extend(_firewall(ctx))
    return out


def _firewall(ctx) -> List[Finding]:
    answers = {}
    ufw = ctx.run(["ufw", "status"])
    if ufw:
        answers["ufw"] = "status: active" in ufw.lower()
    nft = ctx.run(["nft", "list", "ruleset"])
    if nft:
        answers["nftables"] = "hook input" in nft
    ipt = ctx.run(["iptables", "-S"])
    if ipt:
        answers["iptables"] = ("-A " in ipt) or ("-P INPUT DROP" in ipt)
    if not answers:
        ctx.skip(CAT + "/firewall", "sin root no se puede leer el firewall (o no hay ninguno instalado)")
        return []
    if any(answers.values()):
        return []
    return [Finding(
        "NET-003", "No se detecta un firewall con reglas activas", Severity.MEDIUM, CAT,
        "Ninguna de las herramientas consultadas tiene reglas de entrada.",
        "Activar ufw/nftables con política de entrada DROP y permitir solo lo necesario.",
        ["%s: sin reglas" % k for k in answers])]
