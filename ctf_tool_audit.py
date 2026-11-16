#!/usr/bin/env python3
"""Offline, non-invasive CTF solver tool inventory.

Run *inside the solver image*, never just in the Codespaces controller.
Does not access challenge files, answers, network services, or the Docker API.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import sys
from datetime import datetime, timezone

COMMANDS = {
    "common": ["python", "file", "strings", "xxd", "unzip", "7z"],
    "reverse": ["readelf", "objdump", "nm", "gdb"],
    "pwn": ["gcc", "socat", "checksec"],
    "web": ["curl"],
    "forensics": ["exiftool"],
}

MODULES = {
    "crypto": ["Crypto", "sympy", "z3"],
    "reverse": ["elftools"],
    "pwn": ["pwnlib"],
    "web": ["requests", "bs4"],
    "forensics": ["PIL"],
}


def inventory() -> dict:
    tools = {
        category: {
            name: {"available": bool(shutil.which(name)), "path": shutil.which(name)}
            for name in names
        }
        for category, names in COMMANDS.items()
    }
    modules = {
        category: {
            name: bool(importlib.util.find_spec(name)) for name in names
        }
        for category, names in MODULES.items()
    }
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "commands": tools,
        "modules": modules,
    }


def missing_items(report: dict) -> list[str]:
    missing = []
    for group, commands in report["commands"].items():
        missing.extend(
            f"{group}: command {name}"
            for name, info in commands.items()
            if not info["available"]
        )
    for group, modules in report["modules"].items():
        missing.extend(
            f"{group}: Python module {name}"
            for name, available in modules.items()
            if not available
        )
    return missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--strict", action="store_true", help="exit nonzero when a required tool is missing")
    args = parser.parse_args()
    report = inventory()
    missing = missing_items(report)

    if args.json:
        print(json.dumps({**report, "missing": missing}, indent=2, sort_keys=True))
    else:
        print(f"CTF solver audit: Python {report['python']} | UID {report['uid']}")
        for group, commands in report["commands"].items():
            print(f"{group} commands: " + ", ".join(
                f"{name}={'OK' if data['available'] else 'MISSING'}"
                for name, data in commands.items()
            ))
        for group, modules in report["modules"].items():
            print(f"{group} modules: " + ", ".join(
                f"{name}={'OK' if found else 'MISSING'}"
                for name, found in modules.items()
            ))
        print("All required audit tools available." if not missing else f"Missing: {', '.join(missing)}")

    return 1 if args.strict and missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
