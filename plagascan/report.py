# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Renderizado del reporte: texto con colores, JSON y Markdown."""
import json
import platform
import socket
import time
from typing import List, Tuple

from typing import Optional

from .models import Finding, Severity, grade, score_detail

_COLORS = {
    Severity.CRITICAL: "\033[1;41;97m", Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m", Severity.LOW: "\033[36m", Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


def _summary(findings: List[Finding]) -> dict:
    """Puntaje y conteos. Siempre se calcula sobre TODOS los hallazgos, aunque la
    salida se filtre con --min-severity, para que la nota no dependa del filtro."""
    counts = {s.name: 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        counts[f.severity.name] += 1
    pts, raw, capped_by = score_detail(findings)
    return {"score": pts, "grade": grade(pts), "score_before_cap": raw,
            "capped_by": capped_by, "counts": counts}


def _score_line(s: dict) -> str:
    line = "Puntaje: %d/100  Nota: %s" % (s["score"], s["grade"])
    if s["capped_by"]:
        line += "  (limitado por hallazgos %s; por resta serían %d)" % (
            s["capped_by"], s["score_before_cap"])
    return line


def render_json(findings: List[Finding], skipped: List[Tuple[str, str]],
                all_findings: Optional[List[Finding]] = None) -> str:
    ordered = sorted(findings, key=lambda f: -f.severity)
    return json.dumps({
        "host": socket.gethostname(), "kernel": platform.release(),
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "summary": _summary(all_findings if all_findings is not None else findings),
        "findings": [f.to_dict() for f in ordered],
        "skipped": [{"check": c, "reason": r} for c, r in skipped],
    }, indent=2, ensure_ascii=False)


def render_text(findings: List[Finding], skipped: List[Tuple[str, str]], color: bool,
                all_findings: Optional[List[Finding]] = None) -> str:
    def paint(sev: Severity, text: str) -> str:
        return "%s%s%s" % (_COLORS[sev], text, _RESET) if color else text

    lines = []
    s = _summary(all_findings if all_findings is not None else findings)
    lines.append("plagascan - %s (%s)" % (socket.gethostname(), platform.release()))
    lines.append(_score_line(s))
    lines.append("  ".join("%s=%d" % (k, v) for k, v in s["counts"].items()))
    lines.append("")
    for f in sorted(findings, key=lambda f: (-f.severity, f.category, f.id)):
        lines.append("%s %s [%s]" % (paint(f.severity, "[%-8s]" % f.severity.name), f.title, f.id))
        if f.detail:
            lines.append("    %s" % f.detail)
        for e in f.evidence[:8]:
            lines.append("      - %s" % e)
        if len(f.evidence) > 8:
            lines.append("      ... y %d más" % (len(f.evidence) - 8))
        if f.remediation:
            lines.append("    Arreglo: %s" % f.remediation)
        for r in f.references[:2]:
            lines.append("    Ref: %s" % r)
        lines.append("")
    if not findings:
        lines.append("Sin hallazgos.")
    if skipped:
        lines.append("Checks omitidos (probá con sudo para más cobertura):")
        for c, r in skipped:
            lines.append("  - %s: %s" % (c, r))
    return "\n".join(lines)


def render_markdown(findings: List[Finding], skipped: List[Tuple[str, str]],
                    all_findings: Optional[List[Finding]] = None) -> str:
    s = _summary(all_findings if all_findings is not None else findings)
    cap_note = (" — limitado por hallazgos %s; por resta serían %d" % (
        s["capped_by"], s["score_before_cap"])) if s["capped_by"] else ""
    md = ["# Reporte de hardening", "",
          "- Host: `%s` (kernel %s)" % (socket.gethostname(), platform.release()),
          "- Puntaje: **%d/100** (nota %s)%s" % (s["score"], s["grade"], cap_note), "",
          "| Severidad | Cantidad |", "|---|---|"]
    md += ["| %s | %d |" % (k, v) for k, v in s["counts"].items()]
    md.append("")
    for f in sorted(findings, key=lambda f: (-f.severity, f.category, f.id)):
        md.append("## [%s] %s (`%s`)" % (f.severity.name, f.title, f.id))
        if f.detail:
            md.append(f.detail)
        if f.evidence:
            md.append("")
            md += ["- `%s`" % e for e in f.evidence[:10]]
        if f.remediation:
            md += ["", "**Arreglo:** %s" % f.remediation]
        md += ["", *("Ref: %s" % r for r in f.references[:2]), ""]
    if skipped:
        md += ["## Checks omitidos", ""] + ["- **%s**: %s" % (c, r) for c, r in skipped]
    return "\n".join(md)
