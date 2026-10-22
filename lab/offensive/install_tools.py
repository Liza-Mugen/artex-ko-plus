"""Build-time installation of pinned official releases with checksum validation."""
import argparse
import hashlib
import io
import json
import platform
from pathlib import Path
import re
import time
import urllib.request
import zipfile


def download(url):
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AegisLoop-build"})
            with urllib.request.urlopen(req, timeout=120) as response:
                content = response.read(128 * 1024 * 1024 + 1)
                if len(content) > 128 * 1024 * 1024:
                    raise ValueError("tool release exceeds download limit")
                return content
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def install(name, version, arch, destination):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("an explicit release version is required")
    filename = f"{name}_{version}_linux_{arch}.zip"
    base = f"https://github.com/projectdiscovery/{name}/releases/download/v{version}"
    checksum_name = f"katana-{version}-checksums.txt" if name == "katana" else f"{name}_{version}_checksums.txt"
    checksums = download(f"{base}/{checksum_name}").decode("utf-8")
    expected = None
    for line in checksums.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == filename:
            expected = parts[0]
    if not expected or not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        raise ValueError(f"release checksum missing for {filename}")
    archive = download(f"{base}/{filename}")
    actual = hashlib.sha256(archive).hexdigest()
    if actual.lower() != expected.lower():
        raise ValueError(f"release checksum mismatch for {filename}")
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        info = z.getinfo(name)
        if info.file_size > 256 * 1024 * 1024:
            raise ValueError("tool binary exceeds size limit")
        output = destination / name
        output.write_bytes(z.read(info))
        output.chmod(0o755)
        license_dir = Path("/usr/share/doc/aegis-diagnostic-tools") / name
        license_dir.mkdir(parents=True, exist_ok=True)
        for entry in z.infolist():
            if Path(entry.filename).name.lower().startswith(("license", "notice")) and entry.file_size < 1024 * 1024:
                (license_dir / Path(entry.filename).name).write_bytes(z.read(entry))
    return {"tool": name, "version": version, "architecture": arch, "url": f"{base}/{filename}", "sha256": actual}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--arch", default="")
    for tool in ("httpx", "katana", "nuclei"):
        p.add_argument(f"--{tool}", required=True)
    args = p.parse_args()
    arch = args.arch or {"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine(), "")
    if arch not in ("arm64", "amd64"):
        raise ValueError("only linux amd64 and arm64 are supported")
    dest = Path("/usr/local/bin")
    dest.mkdir(parents=True, exist_ok=True)
    manifest = [install(name, getattr(args, name), arch, dest) for name in ("httpx", "katana", "nuclei")]
    Path("/usr/share/aegis-diagnostic-tools.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
