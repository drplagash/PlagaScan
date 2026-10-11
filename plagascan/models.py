# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Modelos de datos: severidad, hallazgos y puntaje."""
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Dict, List, Optional, Tuple


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            raise ValueError("severidad desconocida: %r" % name)


# Cuántos puntos resta cada hallazgo al puntaje (100 = sin hallazgos).
WEIGHTS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    detail: str = ""
    remediation: str = ""
    evidence: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


# Techo del puntaje según el peor hallazgo. Restar puntos no alcanza: sin esto, un solo
# CRITICAL dejaba una "B" y un HIGH una "A". Un equipo con un hallazgo grave no puede
# sacar buena nota por tener todo lo demás en orden.
CAPS = (
    (Severity.CRITICAL, 39),   # cualquier CRITICAL -> nota F
    (Severity.HIGH, 74),       # cualquier HIGH     -> como mucho nota C
)


def score_detail(findings: List[Finding]) -> Tuple[int, int, Optional[str]]:
    """(puntaje final, puntaje por resta, severidad que puso el techo o None)."""
    raw = max(0, 100 - sum(WEIGHTS[f.severity] for f in findings))
    for severity, cap in CAPS:
        if any(f.severity == severity for f in findings):
            if raw > cap:
                return cap, raw, severity.name
            return raw, raw, None
    return raw, raw, None


def score(findings: List[Finding]) -> int:
    return score_detail(findings)[0]


def grade(points: int) -> str:
    for limit, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if points >= limit:
            return letter
    return "F"
