#!/usr/bin/env python3
"""Package source only; never include data, credentials, input ZIPs or caches."""
import hashlib
from pathlib import Path
import sys
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from studio import __version__


def main():
    files = []
    for directory in ("studio", "deploy", "tests", "tools", "docs"):
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                files.append(path)
    files += [ROOT / name for name in ("README.md", "README_AR.md", "ARCHITECTURE.md", "DESIGN.md", "VALIDATION.md", "start.sh", "install-debian.sh")]
    files.sort()
    checksum = ROOT / "SHA256SUMS"
    checksum.write_text("".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(ROOT)}\n" for path in files))
    files.append(checksum)
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    archive = output / f"Shodan-Studio-{__version__}-Debian12.zip"
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as bundle:
        for path in sorted(files):
            entry = ZipInfo("shodan-studio/" + str(path.relative_to(ROOT)), date_time=(2026, 10, 24, 0, 0, 0))
            entry.compress_type = ZIP_DEFLATED
            entry.external_attr = (0o100755 if path.suffix == ".sh" else 0o100644) << 16
            bundle.writestr(entry, path.read_bytes())
    print(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}")


if __name__ == "__main__":
    main()
