"""Locate IDA installs: macOS .app bundles (Spotlight) or Windows install dirs.

`find_ida()` dispatches to the current platform's resolver.
"""

import os
from pathlib import Path
import plistlib
import re
import subprocess


def _read_ida_app_version(app_path: Path) -> tuple[int, ...]:
    """Parse IDA version from the app bundle's Info.plist."""
    info_plist = app_path / "Contents" / "Info.plist"
    try:
        with info_plist.open("rb") as f:
            data = plistlib.load(f)
    except Exception as exc:
        raise SystemExit(f"failed to read Info.plist: {info_plist} ({exc})") from exc

    ver = data.get("CFBundleShortVersionString")
    if not isinstance(ver, str) or not ver.strip():
        raise SystemExit(f"missing CFBundleShortVersionString in Info.plist: {info_plist}")

    ver = ver.strip()
    m = re.match(r"^([0-9]+(?:\.[0-9]+)*)", ver)
    if not m:
        raise SystemExit(f"invalid CFBundleShortVersionString in Info.plist: {info_plist} (value: {ver!r})")

    return tuple(int(x) for x in m.group(1).split("."))


def find_ida_app_bundle_macos() -> Path:
    """Find the newest installed IDA Professional .app using Spotlight."""
    res = subprocess.run(
        ["mdfind", "kMDItemFSName == 'IDA Professional*.app'"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if res.returncode != 0:
        err = (res.stderr or "").strip()
        raise SystemExit(
            "mdfind failed while searching for IDA installations. "
            "Pass --ida explicitly.\n" + (f"mdfind stderr: {err}" if err else "")
        )

    candidates: list[Path] = []
    for line in res.stdout.splitlines():
        p = Path(line.strip())
        if p.suffix == ".app" and p.exists():
            candidates.append(p)

    if not candidates:
        raise SystemExit(
            "No IDA Professional .app bundles found via Spotlight. "
            "Install IDA or pass --ida '/Applications/IDA Professional X.Y.app'."
        )

    best: Path | None = None
    best_ver: tuple[int, ...] = ()
    errors: list[str] = []

    for p in sorted(set(candidates)):
        try:
            ver = _read_ida_app_version(p)
        except SystemExit as exc:
            errors.append(f"{p}: {exc}")
            continue
        if ver > best_ver:
            best_ver = ver
            best = p

    if best is None:
        msg = "\n".join(f"- {x}" for x in errors) if errors else "(none)"
        raise SystemExit(
            "IDA installations found via Spotlight, but none could be version-parsed.\n"
            + msg
            + "\n\nPass --ida explicitly."
        )

    return best


_IDA_EXE_NAMES = ("ida64.exe", "ida.exe")


def _parse_dir_version(dirname: str) -> tuple[int, ...] | None:
    m = re.search(r"([0-9]+(?:\.[0-9]+)*)", dirname)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def find_ida_windows() -> Path:
    """Find the IDA launcher exe in the newest install dir on Windows.

    Candidate roots: ``%ProgramFiles%``, ``%ProgramFiles(x86)%``, and
    ``%LOCALAPPDATA%\\Programs`` (per-user installs). Inside each, dirs named
    *IDA* are scanned for the launcher; the install whose dir name parses the
    highest numeric version (mirroring the macOS version-picking logic) wins.
    Falls back to the first launcher found if no dir name carries a version.

    Raises SystemExit with a hint when no install is found; pass ``--ida`` to
    point at an explicit exe.
    """
    roots: list[Path] = []
    for var in ("ProgramFiles", "ProgramFiles(x86)"):
        value = os.environ.get(var)
        if value:
            roots.append(Path(value))
    if os.environ.get("LOCALAPPDATA"):
        roots.append(Path(os.environ["LOCALAPPDATA"]) / "Programs")

    candidates: list[tuple[tuple[int, ...] | None, Path]] = []  # (version, exe)
    for root in roots:
        try:
            entries = list(root.glob("*"))
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir() or "ida" not in entry.name.lower():
                continue
            for name in _IDA_EXE_NAMES:
                exe = entry / name
                if exe.is_file():
                    candidates.append((_parse_dir_version(entry.name), exe))
                    break

    if not candidates:
        raise SystemExit(
            "No IDA installation found on this machine. "
            "Pass --ida 'C:\\Program Files\\IDA Professional 9.3\\ida.exe'."
        )

    # Highest parseable version wins; unversioned dirs serve as a fallback.
    versioned = [(v, exe) for v, exe in candidates if v is not None]
    pool = versioned or candidates
    best = max(pool, key=lambda item: (item[0], item[1]))

    return best[1]


def find_ida() -> Path:
    """Locate the IDA launcher for the current platform.

    Windows: the launcher exe (``ida64.exe``/``ida.exe``). Anything else
    (macOS): the ``IDA Professional*.app`` bundle.
    """
    if os.name == "nt":
        return find_ida_windows()
    return find_ida_app_bundle_macos()
