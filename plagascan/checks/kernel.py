# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Parámetros del kernel (sysctl) relevantes para seguridad."""
from typing import Callable, List, Optional, Tuple

from . import register
from ..models import Finding, Severity

CAT = "kernel"

# (ruta en /proc/sys, comprobación de "valor bueno", severidad, título, consejo)
Check = Tuple[str, Callable[[int], bool], Severity, str, str]

SYSCTLS: List[Check] = [
    ("kernel/randomize_va_space", lambda v: v == 2, Severity.MEDIUM,
     "ASLR no está completo", "sysctl -w kernel.randomize_va_space=2"),
    ("kernel/kptr_restrict", lambda v: v >= 1, Severity.LOW,
     "Punteros del kernel visibles para usuarios", "kernel.kptr_restrict=1 (o 2)"),
    ("kernel/dmesg_restrict", lambda v: v == 1, Severity.LOW,
     "dmesg legible por usuarios sin privilegios", "kernel.dmesg_restrict=1"),
    ("kernel/yama/ptrace_scope", lambda v: v >= 1, Severity.MEDIUM,
     "ptrace sin restricciones entre procesos", "kernel.yama.ptrace_scope=1"),
    ("kernel/unprivileged_bpf_disabled", lambda v: v >= 1, Severity.MEDIUM,
     "BPF disponible para usuarios sin privilegios", "kernel.unprivileged_bpf_disabled=1"),
    ("fs/protected_symlinks", lambda v: v == 1, Severity.MEDIUM,
     "protected_symlinks desactivado (ataques por enlaces en /tmp)", "fs.protected_symlinks=1"),
    ("fs/protected_hardlinks", lambda v: v == 1, Severity.MEDIUM,
     "protected_hardlinks desactivado", "fs.protected_hardlinks=1"),
    ("fs/suid_dumpable", lambda v: v == 0, Severity.LOW,
     "Los procesos SUID pueden generar core dumps", "fs.suid_dumpable=0"),
    ("net/ipv4/conf/all/accept_redirects", lambda v: v == 0, Severity.LOW,
     "Se aceptan ICMP redirects", "net.ipv4.conf.all.accept_redirects=0"),
    ("net/ipv4/conf/all/send_redirects", lambda v: v == 0, Severity.LOW,
     "El host envía ICMP redirects", "net.ipv4.conf.all.send_redirects=0"),
    ("net/ipv4/conf/all/accept_source_route", lambda v: v == 0, Severity.MEDIUM,
     "Se acepta enrutamiento de origen (source routing)", "net.ipv4.conf.all.accept_source_route=0"),
    ("net/ipv4/conf/all/rp_filter", lambda v: v >= 1, Severity.LOW,
     "Reverse path filtering desactivado (spoofing)", "net.ipv4.conf.all.rp_filter=1"),
    ("net/ipv4/tcp_syncookies", lambda v: v == 1, Severity.LOW,
     "SYN cookies desactivadas", "net.ipv4.tcp_syncookies=1"),
]


@register(CAT, "Parámetros del kernel")
def check_kernel(ctx) -> List[Finding]:
    out: List[Finding] = []
    read_any = False
    for idx, (path, ok, sev, title, advice) in enumerate(SYSCTLS, 1):
        raw = ctx.read("/proc/sys/" + path)
        if raw is None:
            continue
        read_any = True
        try:
            value = int(raw.strip().split()[0])
        except (ValueError, IndexError):
            continue
        if not ok(value):
            out.append(Finding(
                "KER-%03d" % idx, title, sev, CAT,
                "Valor actual de %s: %d." % (path.replace("/", "."), value),
                advice + "  (persistir en /etc/sysctl.d/99-hardening.conf)",
                ["%s = %d" % (path.replace("/", "."), value)]))
    if not read_any:
        ctx.skip(CAT, "/proc/sys no está disponible")
    return out
