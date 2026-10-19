#!/usr/bin/env python3
"""Rebuilds ../Invoke-NetScalerHunt.ps1 from Invoke-NetScalerHunt.template.ps1 and nshunt_engine.py (both in this
folder), then rewrites ../SHA256SUMS.txt. Run it after editing the engine, the template or the README:

    python build.py

The engine is embedded in a PowerShell here-string, so no engine line may start with '@. Both source files must be
plain ASCII (Windows PowerShell 5.1 reads files without a byte order mark as the local ANSI code page).
"""
import hashlib
from pathlib import Path

SRC = Path(__file__).resolve().parent
ROOT = SRC.parent
RELEASE_FILES = ["Invoke-NetScalerHunt.ps1", "README.md", "src/Invoke-NetScalerHunt.template.ps1", "src/build.py",
                 "src/nshunt_engine.py"]


def main():
    eng = (SRC / "nshunt_engine.py").read_text(encoding="ascii").replace("\r\n", "\n")
    if not eng.endswith("\n"):
        eng += "\n"
    bad = [i for i, line in enumerate(eng.split("\n"), 1) if line.startswith("'@")]
    if bad:
        raise SystemExit(f"engine lines start with '@ (they would end the here-string): {bad}")
    engine_sha = hashlib.sha256(eng.encode("ascii")).hexdigest()
    tpl = (SRC / "Invoke-NetScalerHunt.template.ps1").read_text(encoding="ascii")
    if tpl.count("__ENGINE_TEXT__") != 1 or tpl.count("__ENGINE_SHA256__") != 2:
        raise SystemExit("the template must hold __ENGINE_TEXT__ once and __ENGINE_SHA256__ twice")
    out = tpl.replace("__ENGINE_SHA256__", engine_sha).replace("__ENGINE_TEXT__", eng[:-1])
    out = out.replace("\r\n", "\n").replace("\n", "\r\n")          # Windows line endings
    data = out.encode("ascii")
    (ROOT / "Invoke-NetScalerHunt.ps1").write_bytes(data)
    print(f"engine sha256 {engine_sha} | Invoke-NetScalerHunt.ps1: {len(data):,} bytes, "
          f"sha256 {hashlib.sha256(data).hexdigest()}")
    lines = []
    for rel in RELEASE_FILES:
        p = ROOT / rel
        if p.is_file():
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}")
    (ROOT / "SHA256SUMS.txt").write_bytes(("\n".join(lines) + "\n").encode("ascii"))
    print(f"SHA256SUMS.txt: {len(lines)} files")


if __name__ == "__main__":
    main()
