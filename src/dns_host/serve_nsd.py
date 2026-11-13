"""Wait for nsd.conf, install control keys, and exec NSD in the foreground.

NSD binds port 53 as root, then drops to the ``nsd`` user. State it must
write after that drop lives under ``/opt/data/nsd``, which is chowned first.
The pid file and control socket stay on the ``/run`` tmpfs.
"""

from __future__ import annotations

import os
import pwd
import time
from pathlib import Path

from dns_host.config import Settings, log_effective
from dns_host.nsdconf import ensure_control_keys, nsd_conf_path, write_nsd_config


def _chown_tree(directory: Path, user: str) -> None:
    account = pwd.getpwnam(user)
    for root, dirs, files in os.walk(directory):
        os.chown(root, account.pw_uid, account.pw_gid)
        for name in dirs + files:
            os.chown(os.path.join(root, name), account.pw_uid, account.pw_gid)


def main() -> None:
    settings = Settings.load()
    settings.require_service_ns()
    log_effective(settings)
    path = nsd_conf_path(settings)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "zones").mkdir(parents=True, exist_ok=True)
    (directory / "xfr").mkdir(parents=True, exist_ok=True)
    runtime = Path("/run/nsd")
    runtime.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + 30
    while not path.is_file() and time.time() < deadline:
        time.sleep(0.2)
    if not path.is_file():
        write_nsd_config(settings, [settings.catalog_zone.to_text()])
    ensure_control_keys(directory)
    _chown_tree(directory, "nsd")
    _chown_tree(runtime, "nsd")
    os.execvp("nsd", ["nsd", "-d", "-c", str(path)])


if __name__ == "__main__":
    main()
