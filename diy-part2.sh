#!/bin/bash
#
# https://github.com/P3TERX/Actions-OpenWrt
# File name: diy-part2.sh
# Description: OpenWrt DIY script part 2 (After Update feeds)
#
# Copyright (c) 2019-2024 P3TERX <https://p3terx.com>
#
# This is free software, licensed under the MIT License.
# See /LICENSE for more information.

set -e

# Modify default IP
sed -i 's/192.168.1.1/192.168.31.1/g' package/base-files/files/bin/config_generate

# Modify default theme
sed -i 's/luci-theme-bootstrap/luci-theme-argon/g' feeds/luci/collections/luci/Makefile

# Modify hostname
sed -i 's/OpenWrt/Sheep-Router/g' package/base-files/files/bin/config_generate

# Update sing-box from OpenWrt packages master because immortalwrt/packages may lag
# behind sing-box stable releases. This keeps CONFIG_PACKAGE_sing-box-tiny=y in
# .config effective by refreshing the feed package and re-installing its package
# symlink before the final defconfig/build steps.
update_sing_box_from_openwrt() {
  local sing_box_src="/tmp/openwrt-packages-sing-box"
  local sing_box_dst="feeds/packages/net/sing-box"

  echo "==> Updating sing-box package from openwrt/packages master"
  rm -rf "${sing_box_src}" "${sing_box_dst}"
  mkdir -p "$(dirname "${sing_box_dst}")"

  if git clone --depth 1 --filter=blob:none --sparse https://github.com/openwrt/packages "${sing_box_src}"; then
    git -C "${sing_box_src}" sparse-checkout set net/sing-box
    cp -a "${sing_box_src}/net/sing-box" "${sing_box_dst}"
  else
    echo "==> Sparse clone failed; falling back to GitHub tarball download"
    mkdir -p "${sing_box_src}"
    curl -fsSL https://github.com/openwrt/packages/archive/refs/heads/master.tar.gz \
      | tar -xz --strip-components=3 -C "${sing_box_src}" packages-master/net/sing-box
    cp -a "${sing_box_src}" "${sing_box_dst}"
  fi

  rm -rf "${sing_box_src}"

  if [ -x ./scripts/feeds ]; then
    ./scripts/feeds install -f -p packages sing-box
  fi

  if grep -q '^PKG_VERSION:=' "${sing_box_dst}/Makefile"; then
    echo "==> sing-box package version: $(sed -n 's/^PKG_VERSION:=//p' "${sing_box_dst}/Makefile")"
  fi
}

# Keep HomeProxy's generated JSON aligned with the sing-box version selected above.
# The compatibility layer patches the generator, not /etc/init.d/homeproxy, so the
# generated config itself is valid and the workaround is preserved across restarts.
patch_homeproxy_sing_box_compat() {
  local patch_script="$(pwd)/patches/homeproxy-singbox-compat.sh"

  if [ ! -f "${patch_script}" ]; then
    echo "==> ERROR: missing ${patch_script}"
    return 1
  fi

  chmod +x "${patch_script}"
  "${patch_script}"
}

update_sing_box_from_openwrt
patch_homeproxy_sing_box_compat

# echo "==> 更新 adguardhome 到最新版本"
# rm -rf feeds/packages/net/adguardhome
# git clone --depth 1 https://github.com/kenzok8/openwrt-packages tmp-kenzo
# mv tmp-kenzo/adguardhome feeds/packages/net/
# rm -rf tmp-kenzo
# sed -i '\#files/adguardhome#d' feeds/packages/net/adguardhome/Makefile
# sed -i '\#\$(INSTALL_DIR) \$(1)/etc#d' feeds/packages/net/adguardhome/Makefile
