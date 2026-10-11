# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Paquetes sin actualizar y CVEs conocidos de los servicios expuestos."""
import json
import os
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

from . import register
from ..models import Finding, Severity

CAT = "packages"

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
MAX_DETAIL_LOOKUPS = 40


def parse_os_release(text: Optional[str]) -> Dict[str, str]:
    info = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            info[k.strip()] = v.strip().strip('"')
    return info


def parse_apt_upgradable(text: str) -> List[Dict[str, str]]:
    """Líneas: 'openssl/stable-security 3.0.11-1 amd64 [upgradable from: 3.0.9-1]'."""
    rows = []
    for line in text.splitlines():
        if "upgradable" not in line or "/" not in line:
            continue
        name, _, rest = line.partition("/")
        suite = rest.split()[0] if rest.split() else ""
        parts = rest.split()
        rows.append({
            "name": name, "suite": suite,
            "new": parts[1] if len(parts) > 1 else "",
            "security": "security" in suite.lower(),
        })
    return rows


def parse_rpm_check_update(text: str) -> List[Dict[str, str]]:
    rows = []
    for line in text.splitlines():
        f = line.split()
        if len(f) == 3 and "." in f[0] and not line.startswith(("Last metadata", "Obsoleting")):
            rows.append({"name": f[0], "new": f[1], "suite": f[2], "security": True})
    return rows


def osv_ecosystem(info: Dict[str, str]) -> Optional[str]:
    distro, ver = info.get("ID", ""), info.get("VERSION_ID", "")
    if distro == "debian" and ver:
        return "Debian:%s" % ver.split(".")[0]
    if distro == "ubuntu" and ver:
        try:
            major, minor = (int(x) for x in ver.split(".")[:2])
            lts = minor == 4 and major % 2 == 0
        except ValueError:
            lts = False
        return "Ubuntu:%s%s" % (ver, ":LTS" if lts else "")
    return None


def extract_vuln(detail: dict, vid: str, pkg: str, eco: str) -> Tuple[List[str], List[str]]:
    """CVEs y versiones corregidas de un aviso OSV, solo para (pkg, eco).

    Los avisos de Debian (DSA/DLA) traen los CVE en `upstream` y mezclan
    varias releases en `affected`; hay que filtrar por nuestro ecosistema.
    """
    ids = list(detail.get("aliases", [])) + list(detail.get("upstream", []))
    cves = sorted({i for i in ids if i.startswith("CVE-")}) or [vid]
    fixed = set()
    for aff in detail.get("affected", []):
        p = aff.get("package", {})
        if p.get("name") != pkg or p.get("ecosystem") != eco:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.add(ev["fixed"])
    return cves, sorted(fixed)


def _http_json(url: str, body: Optional[dict] = None, timeout: int = 20) -> Optional[dict]:
    try:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, OSError, ValueError):
        return None


@register(CAT, "Actualizaciones pendientes y CVEs de servicios")
def check_packages(ctx) -> List[Finding]:
    out: List[Finding] = []
    info = parse_os_release(ctx.read("/etc/os-release"))
    family = (info.get("ID_LIKE", "") + " " + info.get("ID", "")).lower()

    pending: List[Dict[str, str]] = []
    if "debian" in family or "ubuntu" in family:
        text = ctx.run(["apt", "list", "--upgradable"], timeout=60)
        if text is None:
            ctx.skip(CAT, "no se pudo ejecutar apt")
        else:
            pending = parse_apt_upgradable(text)
    elif any(x in family for x in ("rhel", "fedora", "centos", "rocky", "almalinux")):
        text = ctx.run(["dnf", "-q", "check-update", "--security"], timeout=120)
        if text is None:
            ctx.skip(CAT, "no se pudo ejecutar dnf")
        else:
            pending = parse_rpm_check_update(text)
    else:
        ctx.skip(CAT, "distribución no soportada para actualizaciones pendientes")

    sec = [p for p in pending if p["security"]]
    other = [p for p in pending if not p["security"]]
    if sec:
        out.append(Finding(
            "PKG-001", "%d actualizaciones de seguridad pendientes" % len(sec),
            Severity.HIGH if len(sec) >= 10 else Severity.MEDIUM, CAT,
            "Hay parches de seguridad publicados que todavía no están instalados.",
            "apt update && apt upgrade  (o dnf upgrade --security)",
            ["%s -> %s" % (p["name"], p["new"]) for p in sec[:20]]))
    if other:
        out.append(Finding(
            "PKG-002", "%d actualizaciones normales pendientes" % len(other), Severity.LOW, CAT,
            "Paquetes con versión nueva disponible.", "apt upgrade",
            ["%s -> %s" % (p["name"], p["new"]) for p in other[:10]]))

    if ctx.exists("/var/run/reboot-required") or ctx.exists("/run/reboot-required"):
        out.append(Finding(
            "PKG-003", "Reinicio pendiente", Severity.LOW, CAT,
            "Se instaló un kernel o una librería crítica que requiere reiniciar.",
            "Reiniciar en una ventana de mantenimiento.", []))

    if ctx.online:
        out.extend(_online_cves(ctx, info))
    return out


# --- CVEs vía OSV.dev (solo con --online) -----------------------------------------

def _owning_package(ctx, binary: str) -> Optional[Tuple[str, str]]:
    """(paquete fuente, versión fuente) del paquete dpkg que contiene `binary`."""
    real = ctx.run(["readlink", "-f", binary])
    path = (real or binary).strip()
    owner = ctx.run(["dpkg", "-S", path])
    if not owner or ":" not in owner:
        return None
    pkg = owner.split(":")[0].strip()
    q = ctx.run(["dpkg-query", "-W", "-f=${source:Package}\t${source:Version}\n", pkg])
    if not q or "\t" not in q:
        return None
    src, ver = q.strip().splitlines()[0].split("\t", 1)
    return (src, ver) if src and ver else None


def _collect_targets(ctx) -> Dict[Tuple[str, str], List[str]]:
    """paquete -> motivos por los que se audita (servicio X, SUID Y)."""
    targets: Dict[Tuple[str, str], List[str]] = {}
    for l in ctx.shared.get("listeners", []):  # type: ignore[union-attr]
        if l["host"].startswith("127.") or l["host"] == "::1" or not l["process"]:
            continue
        path = ctx.run(["which", l["process"]])
        if path and path.strip():
            pkg = _owning_package(ctx, path.strip())
            if pkg:
                targets.setdefault(pkg, []).append("servicio %s:%d" % (l["process"], l["port"]))
    for path in ctx.shared.get("suid_paths", [])[:60]:  # type: ignore[union-attr]
        pkg = _owning_package(ctx, path)
        if pkg:
            targets.setdefault(pkg, []).append("SUID %s" % os.path.basename(path))
    return targets


def _online_cves(ctx, info: Dict[str, str]) -> List[Finding]:
    eco = osv_ecosystem(info)
    if not eco:
        ctx.skip(CAT + "/osv", "OSV solo está configurado para Debian y Ubuntu")
        return []
    targets = _collect_targets(ctx)
    if not targets:
        ctx.skip(CAT + "/osv", "no se identificaron paquetes de servicios expuestos")
        return []
    keys = list(targets)
    queries = [{"package": {"name": n, "ecosystem": eco}, "version": v} for n, v in keys]
    resp = _http_json(OSV_BATCH, {"queries": queries})
    if resp is None:
        ctx.skip(CAT + "/osv", "no se pudo contactar a api.osv.dev")
        return []

    hits: List[Tuple[Tuple[str, str], List[str]]] = []
    for key, result in zip(keys, resp.get("results", [])):
        ids = [v["id"] for v in result.get("vulns", [])]
        if ids:
            hits.append((key, ids))

    out: List[Finding] = []
    budget = MAX_DETAIL_LOOKUPS
    for (name, ver), ids in sorted(hits, key=lambda h: -len(h[1])):
        cves, fixed = [], set()
        for vid in ids:
            if budget <= 0:
                cves.append(vid)
                continue
            budget -= 1
            found, fx = extract_vuln(_http_json(OSV_VULN + vid) or {}, vid, name, eco)
            cves.extend(found)
            fixed.update(fx)
        cves = sorted(set(cves))
        sev = Severity.HIGH if len(ids) >= 10 else Severity.MEDIUM
        out.append(Finding(
            "PKG-010", "%s %s: %d vulnerabilidades conocidas" % (name, ver, len(ids)), sev, CAT,
            "Expuesto por: %s. Datos de OSV.dev; incluye avisos de baja prioridad que la "
            "distribución decidió no parchear." % ", ".join(sorted(set(targets[(name, ver)]))),
            "Actualizar el paquete%s." % (" (fix en %s)" % ", ".join(sorted(fixed)[:3]) if fixed else ""),
            cves[:12], ["https://osv.dev/list?q=%s&ecosystem=%s" % (name, eco)]))
    return out
