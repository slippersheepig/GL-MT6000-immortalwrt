#!/bin/bash
# HomeProxy <-> sing-box compatibility layer
#
# This script patches HomeProxy's config generator after feeds are updated.
# It is intentionally version-aware:
#   - sing-box >= 1.13: migrate fields removed in 1.13
#   - sing-box >= 1.14: migrate fields deprecated/introduced by the 1.14 change
#
# It does NOT patch /etc/init.d/homeproxy and does NOT modify the generated JSON
# after HomeProxy has produced it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENWRT_ROOT="${OPENWRT_ROOT:-$(pwd)}"
# The patch script lives in the GitHub workspace while the feed tree lives in /workdir/openwrt.
ROOT_DIR="${OPENWRT_ROOT}"

find_homeproxy_generator() {
    local candidates=(
        "${ROOT_DIR}/feeds/luci/luci-app-homeproxy/root/etc/homeproxy/scripts/generate_client.uc"
        "${ROOT_DIR}/feeds/luci/applications/luci-app-homeproxy/root/etc/homeproxy/scripts/generate_client.uc"
        "${ROOT_DIR}/package/feeds/luci/luci-app-homeproxy/root/etc/homeproxy/scripts/generate_client.uc"
        "${ROOT_DIR}/package/feeds/luci/applications/luci-app-homeproxy/root/etc/homeproxy/scripts/generate_client.uc"
    )

    local p
    for p in "${candidates[@]}"; do
        if [ -f "${p}" ]; then
            printf '%s\n' "${p}"
            return 0
        fi
    done

    find "${ROOT_DIR}/feeds/luci" "${ROOT_DIR}/package/feeds/luci" \
        -type f -path '*/luci-app-homeproxy/root/etc/homeproxy/scripts/generate_client.uc' \
        -print -quit 2>/dev/null || true
}

version_tuple() {
    local v="$1"
    v="$(printf '%s' "$v" | sed -E 's/^[^0-9]*//; s/[^0-9.].*$//')"
    local a b c
    IFS=. read -r a b c _ <<< "$v"
    printf '%d %d %d\n' "${a:-0}" "${b:-0}" "${c:-0}"
}

version_ge() {
    local a1 a2 a3 b1 b2 b3
    read -r a1 a2 a3 <<< "$(version_tuple "$1")"
    read -r b1 b2 b3 <<< "$(version_tuple "$2")"

    if (( a1 != b1 )); then
        (( a1 > b1 ))
        return
    fi
    if (( a2 != b2 )); then
        (( a2 > b2 ))
        return
    fi
    (( a3 >= b3 ))
}

sing_box_version() {
    local makefile="${ROOT_DIR}/feeds/packages/net/sing-box/Makefile"
    if [ ! -f "${makefile}" ]; then
        echo "unknown"
        return 0
    fi
    sed -n 's/^PKG_VERSION:=//p' "${makefile}" | head -n 1
}

patch_with_python() {
    local generator="$1"
    local sb_version="$2"

    GENERATOR="$generator" SB_VERSION="$sb_version" python3 <<'PY'
import os
import re
from pathlib import Path

path = Path(os.environ["GENERATOR"])
sb_version = os.environ["SB_VERSION"]
text = path.read_text(encoding="utf-8")
original = text


def fail(msg):
    raise SystemExit(f"ERROR: {msg}")


def replace_once(old, new, label):
    global text
    count = text.count(old)
    if count != 1:
        fail(f"{label}: expected exactly 1 match, found {count}")
    text = text.replace(old, new, 1)

# -----------------------------
# 1.13 migration: inbound sniff
# -----------------------------
old_sniff_lines = """\tudp_timeout: strToTime(udp_timeout),
\t\tsniff: true,
\t\tsniff_override_destination: strToBool(sniff_override),
\t\tset_system_proxy: false
"""
new_sniff_lines = """\tudp_timeout: strToTime(udp_timeout),
\t\tset_system_proxy: false
"""
if old_sniff_lines in text:
    replace_once(old_sniff_lines, new_sniff_lines, "mixed inbound sniff migration")
else:
    # Already patched upstream: accept only if the old fields are absent.
    if re.search(r'^\s*sniff_override_destination:', text, re.M):
        fail("mixed inbound sniff migration: legacy sniff fields are still present")

for label, old, new in [
    (
        "redirect inbound sniff migration",
        "\t\tlisten_port: int(redirect_port),\n\t\tsniff: true,\n\t\tsniff_override_destination: strToBool(sniff_override)\n",
        "\t\tlisten_port: int(redirect_port)\n",
    ),
    (
        "tproxy inbound sniff migration",
        "\t\tudp_timeout: strToTime(udp_timeout),\n\t\tsniff: true,\n\t\tsniff_override_destination: strToBool(sniff_override)\n",
        "\t\tudp_timeout: strToTime(udp_timeout)\n",
    ),
    (
        "tun inbound sniff migration",
        "\t\tstack: tcpip_stack,\n\t\tsniff: true,\n\t\tsniff_override_destination: strToBool(sniff_override)\n",
        "\t\tstack: tcpip_stack\n",
    ),
]:
    if old in text:
        replace_once(old, new, label)

if re.search(r'^\s*sniff_override_destination:', text, re.M):
    fail("legacy sniff_override_destination remains in generate_client.uc")
if re.search(r'^\s*sniff:\s*true,?\s*$', text, re.M):
    fail("legacy inbound sniff field remains in generate_client.uc")

# Add the new sniff route action once, using the same proxy_mode logic as the
# inbound creation. This preserves mixed/redirect/tproxy/tun coverage.
sniff_marker = "const sniff_inbounds = ['mixed-in'];"
if sniff_marker not in text:
    route_marker = "/* Routing rules start */\n/* Default settings */\n"
    if route_marker not in text:
        fail("cannot locate route configuration insertion point")
    sniff_block = route_marker + """const sniff_inbounds = ['mixed-in'];
if (match(proxy_mode, /redirect/))
\tpush(sniff_inbounds, 'redirect-in');
if (match(proxy_mode, /tproxy/))
\tpush(sniff_inbounds, 'tproxy-in');
if (match(proxy_mode, /tun/))
\tpush(sniff_inbounds, 'tun-in');
"""
    text = text.replace(route_marker, sniff_block, 1)

old_route_rules = """\trules: [
\t\t{
\t\t\tinbound: 'dns-in',
\t\t\taction: 'hijack-dns'
\t\t}
\t\t/*
\t\t * leave for sing-box 1.13.0
\t\t * {
\t\t * \taction: 'sniff'
\t\t * }
\t\t */
\t],
"""
new_route_rules = """\trules: [
\t\t{
\t\t\tinbound: sniff_inbounds,
\t\t\taction: 'sniff'
\t\t},
\t\t{
\t\t\tinbound: 'dns-in',
\t\t\taction: 'hijack-dns'
\t\t}
\t],
"""
if old_route_rules in text:
    replace_once(old_route_rules, new_route_rules, "route sniff action")

# Remove legacy block outbound. HomeProxy's migrate_config already converts
# routing rules using block-out to action=reject, so keeping block-out here is
# unnecessary and incompatible with sing-box >= 1.13.
old_block = """\t{\n\t\ttype: 'block',\n\t\ttag: 'block-out'\n\t},\n"""
if old_block in text:
    replace_once(old_block, "", "legacy block outbound")
elif "type: 'block'" in text and "tag: 'block-out'" in text:
    fail("legacy block outbound found but surrounding syntax changed; refusing an unsafe patch")

# 1.11 migration: direct outbound destination override fields.
old_override = """\t\t/* Direct */
\t\toverride_address: node.override_address,
\t\toverride_port: strToInt(node.override_port),
\t\tproxy_protocol: strToInt(node.proxy_protocol),
"""
new_override = """\t\t/* Direct */
\t\tproxy_protocol: strToInt(node.proxy_protocol),
"""
if old_override in text:
    replace_once(old_override, new_override, "direct outbound destination override")

# 1.11 migration: route rule 'outbound' moved into the route action. The
# route-options fields are moved at the same time so the existing per-rule
# override/tuning settings keep their semantics.
old_rule_action = """\t\t\taction: cfg.action,
\t\t\toutbound: get_outbound(cfg.outbound),
\t\t\toverride_address: cfg.override_address,
\t\t\toverride_port: strToInt(cfg.override_port),
\t\t\tudp_disable_domain_unmapping: strToBool(cfg.udp_disable_domain_unmapping),
\t\t\tudp_connect: strToBool(cfg.udp_connect),
\t\t\tudp_timeout: strToTime(cfg.udp_timeout),
\t\t\ttls_fragment: strToBool(cfg.tls_fragment),
\t\t\ttls_fragment_fallback_delay: strToTime(cfg.tls_fragment_fallback_delay),
\t\t\ttls_record_fragment: strToBool(cfg.tls_record_fragment)
"""
new_rule_action = """\t\t\taction: (cfg.action === 'route') ? {
\t\t\t\taction: 'route',
\t\t\t\toutbound: get_outbound(cfg.outbound),
\t\t\t\toverride_address: cfg.override_address,
\t\t\t\toverride_port: strToInt(cfg.override_port),
\t\t\t\tudp_disable_domain_unmapping: strToBool(cfg.udp_disable_domain_unmapping),
\t\t\t\tudp_connect: strToBool(cfg.udp_connect),
\t\t\t\tudp_timeout: strToTime(cfg.udp_timeout),
\t\t\t\ttls_fragment: strToBool(cfg.tls_fragment),
\t\t\t\ttls_fragment_fallback_delay: strToTime(cfg.tls_fragment_fallback_delay),
\t\t\t\ttls_record_fragment: strToBool(cfg.tls_record_fragment)
\t\t\t} : cfg.action
"""
if old_rule_action in text:
    replace_once(old_rule_action, new_rule_action, "routing rule action migration")

# 1.14 migrations. These new fields must only be emitted when the selected
# sing-box package is actually >= 1.14.0.

def version_tuple(v):
    m = re.match(r'\s*(\d+)\.(\d+)(?:\.(\d+))?', v)
    if not m:
        return (0, 0, 0)
    return tuple(int(x or 0) for x in m.groups())

sb = version_tuple(sb_version)

if sb >= (1, 14, 0):
    # independent_cache was removed conceptually: the new cache is already
    # partitioned by transport. Preserve no stale field.
    old_dns_cache = "\tindependent_cache: strToBool(dns_independent_cache),\n"
    if old_dns_cache in text:
        replace_once(old_dns_cache, "", "independent_cache removal")

    # store_rdrc -> store_dns
    old_store = "\t\t\tstore_rdrc: strToBool(cache_file_store_rdrc),\n"
    new_store = "\t\t\tstore_dns: strToBool(cache_file_store_rdrc),\n"
    if old_store in text:
        replace_once(old_store, new_store, "store_rdrc migration")

    # Remote rule-set download_detour -> http_client (Dial Fields object).
    text = text.replace(
        "\t\t\tdownload_detour: 'main-out'\n",
        "\t\t\thttp_client: { detour: 'main-out' }\n"
    )
    text = text.replace(
        "\t\t\tdownload_detour: get_outbound(cfg.outbound),\n",
        "\t\t\thttp_client: { detour: get_outbound(cfg.outbound) },\n"
    )

    if 'download_detour:' in text:
        fail("download_detour remains after 1.14 migration")

path.write_text(text, encoding="utf-8")

changed = text != original
print(f"HomeProxy compatibility patch: {'changed' if changed else 'already applied'}")
print(f"Generator: {path}")
print(f"sing-box: {sb_version}")
PY
}

main() {
    local generator version
    generator="$(find_homeproxy_generator)"

    if [ -z "${generator}" ]; then
        echo "==> ERROR: HomeProxy generate_client.uc not found"
        return 1
    fi

    version="$(sing_box_version)"
    if [ "${version}" = "unknown" ]; then
        echo "==> WARNING: sing-box PKG_VERSION not found; applying 1.13-safe migration only"
    fi

    echo "==> Patching HomeProxy generator for sing-box ${version}"
    patch_with_python "${generator}" "${version}"
}

main "$@"
