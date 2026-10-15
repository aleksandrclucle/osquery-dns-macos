#!/bin/bash
# Copyright 2026 DNS Events contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OSQUERY_COMMIT=b7538338fa5bf3baeb11d660e0053b5919ed86e2
BUILD_JOBS="${DNS_BUILD_JOBS:-3}"
if [ "$(uname -s)" != Darwin ]; then
  echo "The extension requires macOS. Offline parser tests can run on other platforms." >&2
  exit 1
fi
for tool in git python3 xcrun codesign; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done
python3 -c 'import sys; assert sys.version_info >= (3, 9), "Python 3.9+ is required"'
case "$BUILD_JOBS" in
  ''|*[!0-9]*|0) echo "DNS_BUILD_JOBS must be a positive integer" >&2; exit 1 ;;
esac

mkdir -p "${DNS_CACHE_DIR:-$PROJECT_DIR/.cache}" "$PROJECT_DIR/build"
CACHE_DIR="$(cd "${DNS_CACHE_DIR:-$PROJECT_DIR/.cache}" && pwd)"
OSQUERY_SOURCE="$CACHE_DIR/osquery"
TOOLS_DIR="$CACHE_DIR/build-tools"
SDK_BUILD_DIR="$CACHE_DIR/osquery-build"
DNS_SDK="${SDKROOT:-$(xcrun --sdk macosx --show-sdk-path)}"
export SDKROOT="$DNS_SDK"
if [ ! -d "$DNS_SDK" ]; then
  echo "SDKROOT is not an installed macOS SDK: $DNS_SDK" >&2
  exit 1
fi

if [ ! -x "$TOOLS_DIR/bin/python3" ]; then
  python3 -m venv "$TOOLS_DIR"
fi
if [ ! -x "$TOOLS_DIR/bin/cmake" ] || [ ! -x "$TOOLS_DIR/bin/ninja" ] ||
   ! "$TOOLS_DIR/bin/python3" -c 'from importlib.metadata import version; assert version("cmake") == "3.31.10" and version("ninja") == "1.13.2"' 2>/dev/null; then
  "$TOOLS_DIR/bin/python3" -m pip install --disable-pip-version-check cmake==3.31.10 ninja==1.13.2
fi
if [ ! -e "$OSQUERY_SOURCE/.git" ]; then
  git clone --depth 1 --branch 5.23.1 https://github.com/osquery/osquery.git "$OSQUERY_SOURCE"
fi
if [ "$(git -C "$OSQUERY_SOURCE" rev-parse HEAD)" != "$OSQUERY_COMMIT" ]; then
  echo "Unexpected osquery revision; expected $OSQUERY_COMMIT. Use a dedicated DNS_CACHE_DIR." >&2
  exit 1
fi
EXTENSION_LINK="$OSQUERY_SOURCE/external/extension_dns_events"
if [ -L "$EXTENSION_LINK" ]; then
  python3 - "$EXTENSION_LINK" "$PROJECT_DIR" <<'PY'
from pathlib import Path
import sys
if Path(sys.argv[1]).resolve() != Path(sys.argv[2]).resolve():
    raise SystemExit("SDK extension link belongs to another checkout; use a dedicated DNS_CACHE_DIR")
PY
elif [ -e "$EXTENSION_LINK" ]; then
  echo "SDK extension path already exists and is not a symlink: $EXTENSION_LINK" >&2
  exit 1
else
  ln -s "$PROJECT_DIR" "$EXTENSION_LINK"
fi

"$TOOLS_DIR/bin/cmake" -S "$OSQUERY_SOURCE" -B "$SDK_BUILD_DIR" -G Ninja \
  -DCMAKE_MAKE_PROGRAM="$TOOLS_DIR/bin/ninja" -DCMAKE_OSX_SYSROOT="$DNS_SDK" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 -DCMAKE_BUILD_TYPE=Release \
  -DOSQUERY_VERSION=5.23.1 \
  -DOSQUERY_BUILD_TESTS=OFF -DOSQUERY_BUILD_AWS=OFF -DOSQUERY_BUILD_EXPERIMENTS=OFF \
  -DOSQUERY_NO_DEBUG_SYMBOLS=ON
# Configure fetches the Boost submodule. Apply a compile-only MPL workaround
# for modern Apple Clang; the SDK event and database implementations are intact.
python3 "$PROJECT_DIR/scripts/patch-sdk.py" "$OSQUERY_SOURCE"
"$TOOLS_DIR/bin/cmake" --build "$SDK_BUILD_DIR" --target dns_events --parallel "$BUILD_JOBS"
install -m 0755 "$SDK_BUILD_DIR/external/extension_dns_events/dns_events.ext" "$PROJECT_DIR/build/dns_events.ext"
codesign --force --sign - "$PROJECT_DIR/build/dns_events.ext"
codesign --verify "$PROJECT_DIR/build/dns_events.ext"

# Reuse the generator if offline tests were configured before the SDK build.
"$TOOLS_DIR/bin/cmake" -S "$PROJECT_DIR/tests" -B "$PROJECT_DIR/build/tests" \
  -DCMAKE_OSX_SYSROOT="$DNS_SDK" \
  -DCMAKE_BUILD_TYPE=Release -DDNS_ENABLE_LIVE_TESTS=OFF
"$TOOLS_DIR/bin/cmake" --build "$PROJECT_DIR/build/tests" --parallel "$BUILD_JOBS"
"$TOOLS_DIR/bin/ctest" --test-dir "$PROJECT_DIR/build/tests" --output-on-failure
printf 'Built %s/build/dns_events.ext\n' "$PROJECT_DIR"
