#!/usr/bin/env python3
"""
Download and extract header files for third-party deps we want the decomp to understand.

This script grabs portable source tarballs for OpenSSH, OpenSSL, and XZ Utils,
strips everything except .h files, and drops them under third_party/include/<name>/.
It removes the downloaded tarballs on completion so reruns stay clean.
"""

from __future__ import annotations

import argparse
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Iterable, Set


THIRD_PARTY_SPECS = {
    "openssh": {
        "version": "9.7p1",  # Feb 2024 portable release
        "url": "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.7p1.tar.gz",
        "root_headers": [
            "auth.h",
            "monitor.h",
            "monitor_fdpass.h",
            "packet.h",
            "servconf.h",
            "serverloop.h",
            "session.h",
            "ssh_api.h",
            "sshbuf.h",
            "ssherr.h",
            "sshkey.h",
            "xmalloc.h",
        ],
    },
    "openssl": {
        "version": "3.0.13",  # Latest LTS available in Feb 2024
        "url": "https://www.openssl.org/source/openssl-3.0.13.tar.gz",
        "root_headers": [
            "include/openssl/bio.h",
            "include/openssl/bn.h",
            "include/openssl/core.h",
            "include/openssl/core_dispatch.h",
            "include/openssl/core_names.h",
            "include/openssl/crypto.h",
            "include/openssl/evp.h",
            "include/openssl/obj_mac.h",
            "include/openssl/ossl_typ.h",
            "include/openssl/pem.h",
            "include/openssl/rsa.h",
            "include/openssl/types.h",
        ],
    },
    "xz": {
        "version": "5.4.6",  # Stable pre-backdoor release (Feb 2024 timeframe)
        "url": "https://tukaani.org/xz/xz-5.4.6.tar.gz",
        "root_headers": [
            "src/liblzma/api/lzma.h",
            "src/liblzma/api/lzma/base.h",
            "src/liblzma/api/lzma/check.h",
            "src/liblzma/api/lzma/container.h",
        ],
    },
}


def fetch_and_extract(name: str, url: str, dest_root: Path) -> list[Path]:
    dest_dir = dest_root / name
    if dest_dir.exists():
        # Ensure we refresh cleanly on rerun.
        for path in sorted(dest_dir.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
    dest_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / f"{name}.tar.gz"
        urllib.request.urlretrieve(url, tmp_path)

        extracted_headers: list[Path] = []
        with tarfile.open(tmp_path, "r:gz") as tar:
            members = tar.getmembers()
            if not members:
                return extracted_headers

            top_prefix = members[0].name.split("/", 1)[0]
            for member in members:
                if member.isdir() or not member.name.endswith(".h"):
                    continue
                # Drop the leading top-level directory to keep paths tidy.
                relative = Path(member.name)
                try:
                    relative = relative.relative_to(top_prefix)
                except ValueError:
                    relative = relative.name  # fallback: just the filename
                target_path = dest_dir / relative
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src_fp, open(target_path, "wb") as dst_fp:
                    if src_fp is None:
                        continue
                    dst_fp.write(src_fp.read())
                extracted_headers.append(target_path)
        return extracted_headers


def collect_includes(header_path: Path, root_dir: Path) -> list[Path]:
    includes: list[Path] = []
    try:
        text = header_path.read_text(errors="ignore")
    except OSError:
        return includes
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("#include"):
            continue
        if '"' in line:
            inc = line.split('"')[1]
        elif "<" in line and ">" in line:
            inc = line.split("<", 1)[1].split(">", 1)[0]
        else:
            continue
        inc_path = Path(inc)
        # Prefer relative includes inside this package tree.
        candidates: list[Path] = []
        if not inc_path.is_absolute():
            candidates.append((header_path.parent / inc_path).resolve())
            candidates.append((root_dir / inc_path).resolve())
        else:
            candidates.append(inc_path)
        for cand in candidates:
            try:
                cand.relative_to(root_dir)
            except ValueError:
                continue
            if cand.exists() and cand.suffix == ".h":
                includes.append(cand)
                break
    return includes


def prune_to_relevant(dest_dir: Path, roots: Iterable[str]) -> None:
    root_paths: list[Path] = []
    for rel in roots:
        p = (dest_dir / rel).resolve()
        if p.exists():
            root_paths.append(p)
    keep: Set[Path] = set(root_paths)
    queue = list(root_paths)
    while queue:
        current = queue.pop()
        for dep in collect_includes(current, dest_dir):
            if dep not in keep:
                keep.add(dep)
                queue.append(dep)
    # Remove anything not in keep
    for path in sorted(dest_dir.rglob("*.h")):
        if path not in keep:
            path.unlink()
    # Clean up empty dirs
    for path in sorted(dest_dir.rglob("*"), reverse=True):
        if path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dest",
        default="third_party/include",
        help="Destination root for extracted headers (default: %(default)s)",
    )
    args = parser.parse_args()

    dest_root = Path(args.dest).resolve()
    dest_root.mkdir(parents=True, exist_ok=True)

    for name, spec in THIRD_PARTY_SPECS.items():
        headers = fetch_and_extract(name, spec["url"], dest_root)
        prune_to_relevant(dest_root / name, spec["root_headers"])
        print(
            f"[+] {name} {spec['version']}: kept {sum(1 for _ in (dest_root/name).rglob('*.h'))} headers under {dest_root/name}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
