"""One-line JSON logs.

Records go to syslog (the container's busybox syslogd writes
``/opt/data/log/messages``) and to stdout for a foreground run outside init.
"""

from __future__ import annotations

import json
import sys
import syslog
from datetime import datetime, timezone
from typing import Any

_LEVELS = {
    "error": syslog.LOG_ERR,
    "warning": syslog.LOG_WARNING,
    "info": syslog.LOG_INFO,
}
_opened = False


def log(level: str, msg: str, **fields: Any) -> None:
    global _opened
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "level": level,
        "msg": msg,
    }
    for key, value in fields.items():
        if value is not None:
            record[key] = value
    line = json.dumps(record, default=str, separators=(",", ":"))
    try:
        if not _opened:
            syslog.openlog("dns-host", syslog.LOG_PID, syslog.LOG_DAEMON)
            _opened = True
        syslog.syslog(_LEVELS.get(level, syslog.LOG_INFO), line)
    except OSError:
        pass
    print(line, file=sys.stdout, flush=True)
