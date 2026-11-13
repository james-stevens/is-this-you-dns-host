"""NSD configuration generated from the single secondary list.

``provide-xfr`` and ``notify`` are emitted from that list only, so they
cannot drift. TSIG material comes from ``config.yaml`` (or a secret file it
names). Zone-upload JSON is not an input.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from dns_host.zonesync import atomic_write


def nsd_conf_path(settings) -> Path:
    return Path(settings.data_dir) / "nsd" / "nsd.conf"


def _endpoint(host: str, port: int) -> str:
    if port and int(port) != 53:
        return f"{host}@{int(port)}"
    return host


def _key_token(secondary) -> str:
    name = getattr(secondary, "tsig_key_name", "") or ""
    secret = getattr(secondary, "tsig_secret", "") or ""
    if name and secret:
        return name
    return "NOKEY"


def render_nsd(settings, zone_names: list[str]) -> str:
    """Render nsd.conf. ``zone_names`` are the catalog plus member apexes."""

    lines = [
        "server:",
        "    server-count: 1",
        "    hide-version: yes",
        f"    ip-address: {settings.nsd_bind}",
        f"    port: {int(settings.nsd_port)}",
        "    do-ip4: yes",
        "    do-ip6: no",
        "    verbosity: 2",
        "    log-only-syslog: yes",
        f'    zonesdir: "{Path(settings.data_dir) / "nsd" / "zones"}"',
        f'    xfrdir: "{Path(settings.data_dir) / "nsd" / "xfr"}"',
        f'    cookie-secret-file: "{Path(settings.data_dir) / "nsd" / "cookiesecrets.txt"}"',
        '    pidfile: "/run/nsd/nsd.pid"',
        f'    xfrdfile: "{Path(settings.data_dir) / "nsd" / "xfrd.state"}"',
        f'    zonelistfile: "{Path(settings.data_dir) / "nsd" / "zone.list"}"',
        "    username: nsd",
        "",
        "remote-control:",
        "    control-enable: yes",
        "    control-interface: /run/nsd/nsd.control",
        f'    server-key-file: "{Path(settings.data_dir) / "nsd" / "nsd_server.key"}"',
        f'    server-cert-file: "{Path(settings.data_dir) / "nsd" / "nsd_server.pem"}"',
        f'    control-key-file: "{Path(settings.data_dir) / "nsd" / "nsd_control.key"}"',
        f'    control-cert-file: "{Path(settings.data_dir) / "nsd" / "nsd_control.pem"}"',
        "",
    ]
    seen_keys: set[str] = set()
    for secondary in settings.secondaries:
        name = getattr(secondary, "tsig_key_name", "") or ""
        secret = getattr(secondary, "tsig_secret", "") or ""
        algo = getattr(secondary, "tsig_algo", "") or "hmac-sha256"
        if not name or not secret or name in seen_keys:
            continue
        seen_keys.add(name)
        lines.extend(
            [
                "key:",
                f'    name: "{name}"',
                f"    algorithm: {algo}",
                f'    secret: "{secret}"',
                "",
            ]
        )
    # The hidden master is localhost only. NSD falls back from IXFR to AXFR.
    master = _endpoint("127.0.0.1", int(settings.dns_port))
    lines.extend(
        [
            "pattern:",
            '    name: "relay"',
            f"    request-xfr: {master} NOKEY",
            "    allow-notify: 127.0.0.1 NOKEY",
            "    allow-axfr-fallback: yes",
        ]
    )
    for secondary in settings.secondaries:
        host, port = secondary[0], secondary[1]
        token = _key_token(secondary)
        endpoint = _endpoint(host, port)
        lines.append(f"    provide-xfr: {endpoint} {token}")
        lines.append(f"    notify: {endpoint} {token}")
    lines.append("")
    for name in zone_names:
        zone = name[:-1] if name.endswith(".") else name
        lines.extend(
            [
                "zone:",
                f'    name: "{zone}"',
                '    include-pattern: "relay"',
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def write_nsd_config(settings, zone_names: list[str]) -> Path:
    path = nsd_conf_path(settings)
    atomic_write(path, render_nsd(settings, zone_names))
    _reconfig(path)
    return path


def _reconfig(path: Path) -> None:
    try:
        subprocess.run(
            ["nsd-control", "-c", str(path), "reconfig"],
            check=False,
            timeout=5,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return


def ensure_control_keys(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / "nsd_server.key").is_file() and (directory / "nsd_control.key").is_file():
        return
    setup = "/usr/sbin/nsd-control-setup"
    if not os.path.isfile(setup):
        return
    subprocess.run([setup, "-d", str(directory)], check=False, timeout=20)
