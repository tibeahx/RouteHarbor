include $(TOPDIR)/rules.mk

PKG_NAME:=openrhp
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=OpenRHP contributors
PKG_BUILD_PARALLEL:=1
PKG_FLAGS:=nonshared

# scripts/sdk-build.sh supplies a trusted source tree and pinned host Go runtime.
OPENRHP_SOURCE?=
OPENRHP_GO?=
OPENRHP_GO_VERSION:=go1.27.1

include $(INCLUDE_DIR)/package.mk

OPENRHP_GOARCH:=$(ARCH)
ifeq ($(ARCH),aarch64)
  OPENRHP_GOARCH:=arm64
endif
ifeq ($(ARCH),x86_64)
  OPENRHP_GOARCH:=amd64
endif
ifeq ($(ARCH),i386)
  OPENRHP_GOARCH:=386
endif
ifeq ($(ARCH),mipsel)
  OPENRHP_GOARCH:=mipsle
endif
ifeq ($(ARCH),mips64el)
  OPENRHP_GOARCH:=mips64le
endif
OPENRHP_GOARM:=5
ifneq ($(filter arm_cortex-a% arm_armv7%,$(call qstrip,$(CONFIG_TARGET_ARCH_PACKAGES))),)
  OPENRHP_GOARM:=7
endif
OPENRHP_SUPPORTED_GOARCH:=386 amd64 arm arm64 mips mipsle mips64 mips64le riscv64

# No native engine implementation or executable subscription is bundled here.
define Package/openrhp-guard
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=OpenRHP privileged routing and persistent safety guard
  DEPENDS:=+firewall4 +nftables-json +ip-full +ubus +uci
  USERID:=openrhp:openrhp
endef

define Package/openrhp
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=OpenReverseHomeProxy gateway controller and web UI
  DEPENDS:=+openrhp-guard +ca-bundle
  USERID:=openrhp:openrhp
endef

define Package/openrhp-node
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=OpenRHP paired access-point agent
  DEPENDS:=+ubus +uci +ca-bundle
  USERID:=openrhp-node:openrhp-node
endef

# Optional feature package: core gateway installation does not require it.
define Package/openrhp-conntrack
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=OpenRHP optional scoped connection tracking reset
  DEPENDS:=+openrhp +conntrack
endef

define Package/openrhp-sing-box
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=OpenRHP sing-box adapter dependencies
  DEPENDS:=+openrhp +sing-box +kmod-nft-tproxy +kmod-nft-socket
endef

define Package/openrhp-xray
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=OpenRHP Xray adapter dependencies
  DEPENDS:=+openrhp +xray-core +kmod-nft-tproxy +kmod-nft-socket
endef

define Package/openrhp/description
 OpenWrt gateway control service with an English embedded UI, bounded independent
 probes, source selection and transactional network application. Fresh installs
 leave traffic routing off. Authorize setup through existing administrator access.
endef

define Package/openrhp-guard/description
 Root-only helper, independent rollback process, policy-routing safety guard and
 persistent fw4 include. Kept separately so uninstalling the controller does not
 silently reopen protected traffic. Does not rewrite WAN/LAN/firewall UCI settings.
endef

define Package/openrhp-node/description
 Lightweight TLS paired-node agent and separate privileged UCI helper. It does not
 run an independent channel selector. Pairing requires existing trusted admin access.
endef

define Build/Prepare
	@test -n "$(OPENRHP_SOURCE)" -a -f "$(OPENRHP_SOURCE)/go.mod" || { echo "OPENRHP_SOURCE must name the verified source tree" >&2; exit 1; }
	@test -n "$(OPENRHP_GO)" -a -x "$(OPENRHP_GO)" || { echo "OPENRHP_GO must name the verified Go 1.27.1 binary" >&2; exit 1; }
	@test "`"$(OPENRHP_GO)" version | cut -d ' ' -f 3`" = "$(OPENRHP_GO_VERSION)" || { echo "Unexpected Go toolchain version" >&2; exit 1; }
	$(call Build/Prepare/Default)
	$(CP) "$(OPENRHP_SOURCE)/go.mod" "$(OPENRHP_SOURCE)/LICENSE" $(PKG_BUILD_DIR)/
	$(CP) "$(OPENRHP_SOURCE)/api" "$(OPENRHP_SOURCE)/cmd" "$(OPENRHP_SOURCE)/internal" $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	@test -n "$(filter $(OPENRHP_GOARCH),$(OPENRHP_SUPPORTED_GOARCH))" || { echo "Unsupported Go target: $(ARCH)" >&2; exit 1; }
	mkdir -p $(PKG_BUILD_DIR)/bin
	cd $(PKG_BUILD_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=$(OPENRHP_GOARCH) GOARM=$(OPENRHP_GOARM) GOMIPS=softfloat GOMIPS64=softfloat GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=$(PKG_BUILD_DIR)/.gocache "$(OPENRHP_GO)" build -trimpath -buildvcs=false -ldflags='-s -w -buildid= -X main.version=$(PKG_VERSION)' -o bin/openrhp ./cmd/openrhp
	cd $(PKG_BUILD_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=$(OPENRHP_GOARCH) GOARM=$(OPENRHP_GOARM) GOMIPS=softfloat GOMIPS64=softfloat GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=$(PKG_BUILD_DIR)/.gocache "$(OPENRHP_GO)" build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o bin/openrhp-helper ./cmd/openrhp-helper
	cd $(PKG_BUILD_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=$(OPENRHP_GOARCH) GOARM=$(OPENRHP_GOARM) GOMIPS=softfloat GOMIPS64=softfloat GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=$(PKG_BUILD_DIR)/.gocache "$(OPENRHP_GO)" build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o bin/openrhp-node ./cmd/openrhp-node
endef

define Package/openrhp-guard/install
	$(INSTALL_DIR) $(1)/usr/libexec $(1)/etc/init.d $(1)/etc/openrhp-helper $(1)/usr/share/nftables.d/ruleset-pre
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/openrhp-helper $(1)/usr/libexec/
	$(INSTALL_BIN) ./files/openrhp-guard.init $(1)/etc/init.d/openrhp-guard
	$(INSTALL_DATA) ./files/guard.nft $(1)/etc/openrhp-helper/guard.nft
	chmod 0700 $(1)/etc/openrhp-helper
	chmod 0600 $(1)/etc/openrhp-helper/guard.nft
	$(INSTALL_DATA) ./files/90-openrhp-guard.nft $(1)/usr/share/nftables.d/ruleset-pre/
endef

define Package/openrhp/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/openrhp $(1)/usr/bin/
	$(INSTALL_BIN) ./files/openrhp.init $(1)/etc/init.d/openrhp
	$(INSTALL_CONF) ./files/openrhp.config $(1)/etc/config/openrhp
	$(INSTALL_BIN) ./files/openrhp-setup $(1)/usr/libexec/openrhp-setup
endef

define Package/openrhp-node/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/openrhp-node $(1)/usr/bin/
	$(INSTALL_BIN) ./files/openrhp-node.init $(1)/etc/init.d/openrhp-node
	$(INSTALL_BIN) ./files/openrhp-node-helper.init $(1)/etc/init.d/openrhp-node-helper
	$(INSTALL_CONF) ./files/openrhp-node.config $(1)/etc/config/openrhp-node
	$(INSTALL_BIN) ./files/openrhp-node-setup $(1)/usr/libexec/openrhp-node-setup
endef

define Package/openrhp-conntrack/install
	true
endef

define Package/openrhp-sing-box/install
	true
endef

define Package/openrhp-xray/install
	true
endef

define Package/openrhp/conffiles
/etc/config/openrhp
/etc/openrhp/
endef

define Package/openrhp-guard/conffiles
/etc/openrhp-helper/
endef

define Package/openrhp-node/conffiles
/etc/config/openrhp-node
/etc/openrhp-node/
/etc/openrhp-node-helper/
endef

define Package/openrhp-guard/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
# An upgrade retains the guard package and its conffiles; it still stops guarded.
[ "$$PKG_UPGRADE" = "1" ] && exit 0
/usr/libexec/openrhp-helper can-remove --state-dir /etc/openrhp-helper || {
 echo "OpenRHP still protects traffic. Keep openrhp-guard installed, or explicitly run decommission --policy restore-direct." >&2
 exit 1
}
endef

$(eval $(call BuildPackage,openrhp-guard))
$(eval $(call BuildPackage,openrhp))
$(eval $(call BuildPackage,openrhp-node))
$(eval $(call BuildPackage,openrhp-sing-box))
$(eval $(call BuildPackage,openrhp-xray))

$(eval $(call BuildPackage,openrhp-conntrack))
