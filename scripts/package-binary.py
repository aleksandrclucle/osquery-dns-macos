#!/usr/bin/env python3
# Copyright 2026 DNS Events contributors
# SPDX-License-Identifier: Apache-2.0
"""Package a built macOS extension, configuration examples and dependency notices."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SDK_COMMIT = "b7538338fa5bf3baeb11d660e0053b5919ed86e2"
# Runtime/static libraries and header-only dependencies of the pinned SDK target.
NOTICES = {
    "boost": ["LICENSE_1_0.txt"],
    "gflags": ["COPYING.txt"],
    "glog": ["COPYING"],
    "libarchive": ["COPYING"],
    "rapidjson": ["license.txt"],
    "thrift": ["LICENSE", "NOTICE"],
    "zlib": ["LICENSE"],
    "zstd": ["LICENSE"],
}


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_notices(directory):
    """Retain per-file licenses that the library's top-level license omits."""
    notices = {}
    for source in sorted(directory.rglob("*")):
        if source.suffix not in (".c", ".h") or "test" in source.relative_to(directory).parts:
            continue
        text = source.read_text()
        offset = 0
        while match := re.match(r"\s*(/\*.*?\*/)", text[offset:], re.DOTALL):
            comment = match[1]
            if re.search(r"copyright|redistribution|permission", comment, re.IGNORECASE):
                notices.setdefault(comment, []).append(str(source.relative_to(directory)))
            offset += match.end()
    if not notices:
        raise ValueError("No source license notices found in " + str(directory))
    return "\n\n".join("Files: " + ", ".join(names) + "\n" + comment
                         for comment, names in notices.items()) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "build/dns_events.ext")
    parser.add_argument("--cache-dir", type=Path,
                        default=Path(os.environ.get("DNS_CACHE_DIR", str(ROOT / ".cache"))))
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build/dist")
    parser.add_argument("--architecture", required=True, choices=("arm64", "x86_64"))
    args = parser.parse_args()
    sdk = args.cache_dir / "osquery"
    sdk_build = args.cache_dir / "osquery-build"
    if command("git", "-C", str(sdk), "rev-parse", "HEAD") != SDK_COMMIT:
        raise ValueError("Package notices require the pinned osquery SDK checkout")
    if command("lipo", "-archs", str(args.binary)).split() != [args.architecture]:
        raise ValueError("Binary architecture does not match --architecture")
    subprocess.run(["codesign", "--verify", str(args.binary)], check=True)
    match = re.search(r'startExtension\("dns_events",\s*"([0-9.]+)"',
                      (ROOT / "src/main.cpp").read_text())
    if not match:
        raise ValueError("Cannot identify the extension version in src/main.cpp")
    version = match[1]
    name = f"dns-events-{version}-macos-{args.architecture}"
    files = {"dns_events.ext": args.binary, "LICENSE": ROOT / "LICENSE",
             "README.md": ROOT / "README.md",
             "docs/implementation.md": ROOT / "docs/implementation.md",
             "configs/dns-events.pack.json": ROOT / "configs/dns-events.pack.json",
             "configs/dns.mobileconfig": ROOT / "configs/dns.mobileconfig",
             "licenses/osquery/LICENSE": sdk / "LICENSE",
             "licenses/osquery/LICENSE-Apache-2.0": sdk / "LICENSE-Apache-2.0",
             "licenses/openssl/LICENSE.txt":
                 sdk_build / "openssl/openssl-prefix/src/openssl/LICENSE.txt"}
    for component, names in NOTICES.items():
        for filename in names:
            files[f"licenses/{component}/{filename}"] = (
                sdk / "libraries/cmake/source" / component / "src" / filename)
    sqlite_header = sdk / "libraries/cmake/source/sqlite/src/src/sqlite3.h"
    for source in [*files.values(), sqlite_header]:
        if not source.is_file():
            raise ValueError("Required package file is missing: " + str(source))
    sqlite_text = sqlite_header.read_text()
    if not sqlite_text.startswith("/*") or "author disclaims copyright" not in sqlite_text[:1000]:
        raise ValueError("Unexpected SQLite copyright notice")
    extra_notices = {
        "licenses/libarchive/NOTICES.txt": source_notices(
            sdk / "libraries/cmake/source/libarchive/src/libarchive"),
        "licenses/zstd/NOTICES.txt": source_notices(
            sdk / "libraries/cmake/source/zstd/src/lib"),
        "licenses/sqlite/NOTICE.txt": sqlite_text[:sqlite_text.index("*/") + 2] + "\n",
    }
    revision = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                              text=True, capture_output=True)
    info = {"version": version, "architecture": args.architecture,
            "source_commit": revision.stdout.strip() if revision.returncode == 0 else None,
            "osquery_commit": SDK_COMMIT, "binary_sha256": sha256(args.binary)}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive = args.output_dir / (name + ".tar.gz")
    with tempfile.TemporaryDirectory(prefix="dns-package-") as temporary:
        staging = Path(temporary) / name
        for relative, source in files.items():
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        for relative, notice in extra_notices.items():
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(notice)
        (staging / "BUILD-INFO.json").write_text(json.dumps(info, indent=2) + "\n")

        def metadata(member):
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mtime = 0
            member.mode = 0o755 if member.isdir() or member.name == name + "/dns_events.ext" else 0o644
            return member

        with archive.open("wb") as output, gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as tar:
                tar.add(staging, arcname=name, filter=metadata)
    checksum = archive.with_name(archive.name + ".sha256")
    checksum.write_text(sha256(archive) + "  " + archive.name + "\n")
    print(archive)
    print(checksum)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
