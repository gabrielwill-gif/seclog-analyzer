from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


@dataclass(frozen=True)
class Event:
    """Um evento normalizado extraído de uma linha de log."""

    kind: str  # ssh_failed | ssh_success | http
    ip: str
    timestamp: datetime
    user: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    user_agent: Optional[str] = None


@dataclass
class Alert:
    """Um alerta de segurança gerado por uma regra de detecção."""

    rule: str
    severity: str
    ip: str
    description: str
    count: int
    mitre: str
    first_seen: datetime
    last_seen: datetime

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "ip": self.ip,
            "description": self.description,
            "count": self.count,
            "mitre": self.mitre,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }
