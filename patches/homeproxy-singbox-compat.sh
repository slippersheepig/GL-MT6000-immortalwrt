#!/bin/bash
# HomeProxy <-> sing-box compatibility layer
#
# Current target: sing-box >= 1.12 / 1.13.
#
# HomeProxy's current generator still emits the legacy inbound fields
# `sniff` and `sniff_override_destination` on mixed/redirect/tproxy/tun
# inbounds. sing-box has removed these fields. The upstream HomeProxy change
# proposed on 2026-07-20 removes exactly those fields and leaves the existing
# route-level sniff action commented.
#
# We patch the generator rather than /etc/init.d/homeproxy or generated JSON.

set -euo pipefail

OPENWRT_ROOT="${OPENWRT_ROOT:-$(pwd)}"

find_homeproxy_generator() {
    local candidates=(
        "${OPENWRT_ROOT}/feeds/luci/luci-app-homeproxy/root/etc/homeproxy/scripts/generate_client.uc"
        "${OPENWRT_ROOT}/feeds/luci/applications/luci-app-homeproxy/root/etc/homeproxy/scripts/generate_client.uc"
        "${OPENWRT_ROOT}/package/feeds/luci/luci-app-homeproxy/root/etc/homeproxy/scripts/generate_client.uc"
        "${OPENWRT_ROOT}/package/feeds/luci/applications/luci-app-homeproxy/root/etc/homeproxy/scripts/generate_client.uc"
    )

    local p
    for p in "${candidates[@]}"; do
        if [ -f "${p}" ]; then
            printf '%s\n' "${p}"
            return 0
        fi
    done

    find "${OPENWRT_ROOT}/feeds/luci" "${OPENWRT_ROOT}/package/feeds/luci" \
        -type f \
        -path '*/luci-app-homeproxy/root/etc/homeproxy/scripts/generate_client.uc' \
        -print -quit 2>/dev/null || true
}

sing_box_version() {
    local makefile="${OPENWRT_ROOT}/feeds/packages/net/sing-box/Makefile"

    if [ ! -f "${makefile}" ]; then
        echo "unknown"
        return 0
    fi

    sed -n 's/^PKG_VERSION:=//p' "${makefile}" | head -n 1
}

patch_generator() {
    local generator="$1"

    GENERATOR="${generator}" python3 <<'PY'
import os
import re
from pathlib import Path

path = Path(os.environ["GENERATOR"])
text = path.read_text(encoding="utf-8")
original = text

# Remove only the two legacy inbound property lines. Use line-based matching
# rather than a large multiline replacement so this survives harmless upstream
# formatting changes.
patterns = (
    re.compile(r"^[ \t]*sniff:[ \t]*true,[ \t]*\r?$", re.MULTILINE),
    re.compile(r"^[ \t]*sniff_override_destination:[^\n]*\r?$", re.MULTILINE),
)

before_sniff = len(re.findall(r"^[ \t]*sniff:[ \t]*true,?[ \t]*$", text, re.MULTILINE))
before_override = len(re.findall(r"^[ \t]*sniff_override_destination:", text, re.MULTILINE))

for pattern in patterns:
    text = pattern.sub("", text)

after_sniff = len(re.findall(r"^[ \t]*sniff:[ \t]*true,?[ \t]*$", text, re.MULTILINE))
after_override = len(re.findall(r"^[ \t]*sniff_override_destination:", text, re.MULTILINE))

if after_sniff or after_override:
    raise SystemExit(
        "ERROR: HomeProxy generator still contains legacy inbound sniff fields "
        f"(sniff={after_sniff}, sniff_override_destination={after_override})"
    )

if text != original:
    path.write_text(text, encoding="utf-8")
    changed = "changed"
else:
    changed = "already applied"

print(
    "==> HomeProxy legacy sniff migration: "
    + changed
    + f" (sniff removed={before_sniff}, sniff_override_destination removed={before_override})"
)
print(f"==> Generator: {path}")
PY
}

main() {
    local generator version

    generator="$(find_homeproxy_generator)"
    if [ -z "${generator}" ]; then
        echo "==> ERROR: HomeProxy generate_client.uc not found under ${OPENWRT_ROOT}"
        return 1
    fi

    version="$(sing_box_version)"
    echo "==> sing-box package version: ${version}"
    echo "==> Patching HomeProxy generator for removed inbound sniff fields"

    patch_generator "${generator}"
}

main "$@"
