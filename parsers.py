"""Parsers de linhas de log para eventos normalizados."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from seclog.models import Event

# Exemplo: Nov 13 02:14:01 srv sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 4444 ssh2
SSH_FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+) port \d+"
)
SSH_SUCCESS = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>[\d.]+) port \d+"
)

# Formato "combined" do Apache/Nginx
HTTP = re.compile(
    r"^(?P<ip>[\d.]+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>.+?) HTTP/[\d.]+" (?P<status>\d{3}) \S+'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


def _syslog_time(ts: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int) -> Optional[Event]:
    """Converte uma linha de log em Event. Retorna None se não reconhecida."""
    line = line.rstrip("\n")

    m = SSH_FAILED.match(line)
    if m:
        return Event("ssh_failed", m["ip"], _syslog_time(m["ts"], year), user=m["user"])

    m = SSH_SUCCESS.match(line)
    if m:
        return Event("ssh_success", m["ip"], _syslog_time(m["ts"], year), user=m["user"])

    m = HTTP.match(line)
    if m:
        try:
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None
        return Event(
            "http",
            m["ip"],
            ts,
            method=m["method"],
            path=m["path"],
            status=int(m["status"]),
            user_agent=m["ua"],
        )

    return None
