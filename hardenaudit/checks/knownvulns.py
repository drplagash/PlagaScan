"""Vulnerabilidades locales famosas detectadas por versión (sin red).

Es una heurística: las distribuciones suelen portar el parche sin cambiar el
número de versión upstream. Por eso estos hallazgos se reportan como
"posible" y conviene confirmarlos con `--online` o con el changelog del paquete.
"""
import re
from typing import List, Optional, Tuple

from . import register
from ..models import Finding, Severity

CAT = "knownvulns"


def parse_version(text: str) -> Tuple[int, ...]:
    """'1.9.5p2' -> (1, 9, 5, 2); '5.15.0-91-generic' -> (5, 15, 0, 91)."""
    nums = re.findall(r"\d+", text)
    return tuple(int(n) for n in nums)


def in_range(v: Tuple[int, ...], low: Tuple[int, ...], high_excl: Tuple[int, ...]) -> bool:
    return low <= v < high_excl


def _first_line_version(output: Optional[str], pattern: str) -> Optional[str]:
    if not output:
        return None
    m = re.search(pattern, output)
    return m.group(1) if m else None


@register(CAT, "Vulnerabilidades locales conocidas (por versión)")
def check_known(ctx) -> List[Finding]:
    out: List[Finding] = []

    sudo_v = _first_line_version(ctx.run(["sudo", "-V"]), r"Sudo version ([\w.]+)")
    if sudo_v:
        v = parse_version(sudo_v)
        # CVE-2021-3156 "Baron Samedit": 1.8.2-1.8.31p2 y 1.9.0-1.9.5p1
        if in_range(v, (1, 8, 2), (1, 8, 32)) or in_range(v, (1, 9, 0), (1, 9, 5, 2)):
            out.append(Finding(
                "KV-001", "sudo %s: posible CVE-2021-3156 (Baron Samedit)" % sudo_v,
                Severity.HIGH, CAT,
                "Desbordamiento de heap en sudoedit que da root a cualquier usuario local.",
                "Actualizar sudo (apt/dnf upgrade sudo). Si la distro portó el parche, es un falso positivo.",
                ["sudo -V -> %s" % sudo_v],
                ["https://nvd.nist.gov/vuln/detail/CVE-2021-3156"]))
        # CVE-2025-32463: opción --chroot, 1.9.14 - 1.9.17
        if in_range(v, (1, 9, 14), (1, 9, 17, 1)):
            out.append(Finding(
                "KV-002", "sudo %s: posible CVE-2025-32463 (chroot)" % sudo_v,
                Severity.HIGH, CAT,
                "sudo --chroot permite cargar una biblioteca controlada por el usuario y obtener root.",
                "Actualizar a sudo 1.9.17p1 o superior.",
                ["sudo -V -> %s" % sudo_v],
                ["https://nvd.nist.gov/vuln/detail/CVE-2025-32463"]))

    pk_v = _first_line_version(ctx.run(["pkexec", "--version"]), r"version ([\d.]+)")
    if pk_v and in_range(parse_version(pk_v), (0,), (0, 121)):
        out.append(Finding(
            "KV-003", "polkit %s: posible CVE-2021-4034 (PwnKit)" % pk_v, Severity.MEDIUM, CAT,
            "pkexec con versión upstream < 0.121. Muchas distros portaron el parche sin subir el número.",
            "Verificar que el paquete polkit esté actualizado (apt/dnf changelog polkit).",
            ["pkexec --version -> %s" % pk_v],
            ["https://nvd.nist.gov/vuln/detail/CVE-2021-4034"]))

    uname = (ctx.run(["uname", "-r"]) or "").strip()
    if uname:
        k = parse_version(uname)[:3]
        if len(k) == 3:
            # CVE-2022-0847 "Dirty Pipe": 5.8 <= k < 5.10.102 | 5.15.25 | 5.16.11
            dirty = (
                (5, 8, 0) <= k < (5, 10, 102)
                or (5, 11, 0) <= k < (5, 15, 25)
                or (5, 16, 0) <= k < (5, 16, 11)
            )
            if dirty:
                out.append(Finding(
                    "KV-004", "Kernel %s: posible CVE-2022-0847 (Dirty Pipe)" % uname,
                    Severity.MEDIUM, CAT,
                    "Permite sobrescribir archivos de solo lectura y escalar a root.",
                    "Actualizar el kernel y reiniciar.", ["uname -r -> %s" % uname],
                    ["https://nvd.nist.gov/vuln/detail/CVE-2022-0847"]))
            # CVE-2016-5195 "Dirty COW": < 4.8.3
            if k < (4, 8, 3):
                out.append(Finding(
                    "KV-005", "Kernel %s: posible CVE-2016-5195 (Dirty COW)" % uname,
                    Severity.HIGH, CAT,
                    "Condición de carrera en copy-on-write que permite escritura en archivos de solo lectura.",
                    "Actualizar el kernel y reiniciar.", ["uname -r -> %s" % uname],
                    ["https://nvd.nist.gov/vuln/detail/CVE-2016-5195"]))
    return out
