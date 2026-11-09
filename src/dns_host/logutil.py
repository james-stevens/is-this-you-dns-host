"""One-line JSON logs."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any


def log(level: str, msg: str, **fields: Any) -> None:
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "level": level,
        "msg": msg,
    }
    for key, value in fields.items():
        if value is not None:
            record[key] = value
    print(json.dumps(record, default=str, separators=(",", ":")), file=sys.stdout, flush=True)
