include $(TOPDIR)/rules.mk

PKG_NAME:=routeharbor
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=RouteHarbor contributors
PKG_BUILD_PARALLEL:=1
PKG_FLAGS:=nonshared

# scripts/sdk-build.sh supplies a trusted source tree and pinned host Go runtime.
ROUTEHARBOR_SOURCE?=
ROUTEHARBOR_GO?=
ROUTEHARBOR_GO_VERSION:=go1.27.1

include $(INCLUDE_DIR)/package.mk

# Go already strips symbols/DWARF with -s -w. SDK sstrip truncates the ELF
# section-name table, breaking Go build metadata inspection and package audits.
# This recipe bundles only those Go binaries and scripts; skip its second strip.
RSTRIP:=:

ROUTEHARBOR_GOARCH:=$(ARCH)
ifeq ($(ARCH),aarch64)
  ROUTEHARBOR_GOARCH:=arm64
endif
ifeq ($(ARCH),x86_64)
  ROUTEHARBOR_GOARCH:=amd64
endif
ifeq ($(ARCH),i386)
  ROUTEHARBOR_GOARCH:=386
endif
ifeq ($(ARCH),mipsel)
  ROUTEHARBOR_GOARCH:=mipsle
endif
ifeq ($(ARCH),mips64el)
  ROUTEHARBOR_GOARCH:=mips64le
endif
ROUTEHARBOR_GOARM:=5
ifneq ($(filter arm_cortex-a% arm_armv7%,$(call qstrip,$(CONFIG_TARGET_ARCH_PACKAGES))),)
  ROUTEHARBOR_GOARM:=7
endif
ROUTEHARBOR_SUPPORTED_GOARCH:=386 amd64 arm arm64 mips mipsle mips64 mips64le riscv64

# No native engine implementation or executable subscription is bundled here.
define Package/routeharbor-guard
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=RouteHarbor privileged routing and persistent safety guard
  DEPENDS:=+firewall4 +nftables-json +ip-full +ubus +uci
  USERID:=routeharbor:routeharbor
endef

define Package/routeharbor
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=RouteHarbor gateway controller and web UI
  DEPENDS:=+routeharbor-guard +ca-bundle +conntrack
  USERID:=routeharbor:routeharbor
endef

define Package/routeharbor-node
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=RouteHarbor paired access-point agent
  DEPENDS:=+ubus +uci +ca-bundle
  USERID:=routeharbor-node:routeharbor-node
endef

# Compatibility feature alias. Selective DNS recovery requires conntrack in core.
define Package/routeharbor-conntrack
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=RouteHarbor scoped connection tracking reset compatibility package
  DEPENDS:=+routeharbor +conntrack
endef

# The helper supervises this worker only for an explicitly enabled relay profile.
define Package/routeharbor-continuity
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=RouteHarbor optional private relay session continuity
  DEPENDS:=+routeharbor +kmod-nft-tproxy +kmod-nft-socket
endef

define Package/routeharbor-sing-box
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=RouteHarbor sing-box adapter dependencies
  DEPENDS:=+routeharbor +sing-box +kmod-nft-tproxy +kmod-nft-socket
endef

define Package/routeharbor-xray
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=RouteHarbor Xray adapter dependencies
  DEPENDS:=+routeharbor +xray-core +kmod-nft-tproxy +kmod-nft-socket
endef

define Package/routeharbor/description
 OpenWrt gateway control service with an English embedded UI, bounded independent
 probes, source selection and transactional network application. Fresh installs
 leave traffic routing off. Authorize setup through existing administrator access.
endef

define Package/routeharbor-guard/description
 Root-only helper, independent rollback process, policy-routing safety guard and
 persistent fw4 include. Kept separately so uninstalling the controller does not
 silently reopen protected traffic. Does not rewrite WAN/LAN/firewall UCI settings.
endef

define Package/routeharbor-node/description
 Lightweight TLS paired-node agent and separate privileged UCI helper. It does not
 run an independent channel selector. Pairing requires existing trusted admin access.
endef

define Build/Prepare
	@test -n "$(ROUTEHARBOR_SOURCE)" -a -f "$(ROUTEHARBOR_SOURCE)/go.mod" || { echo "ROUTEHARBOR_SOURCE must name the verified source tree" >&2; exit 1; }
	@test -n "$(ROUTEHARBOR_GO)" -a -x "$(ROUTEHARBOR_GO)" || { echo "ROUTEHARBOR_GO must name the verified Go 1.27.1 binary" >&2; exit 1; }
	@test "`"$(ROUTEHARBOR_GO)" version | cut -d ' ' -f 3`" = "$(ROUTEHARBOR_GO_VERSION)" || { echo "Unexpected Go toolchain version" >&2; exit 1; }
	$(call Build/Prepare/Default)
	$(CP) "$(ROUTEHARBOR_SOURCE)/go.mod" "$(ROUTEHARBOR_SOURCE)/LICENSE" $(PKG_BUILD_DIR)/
	$(CP) "$(ROUTEHARBOR_SOURCE)/api" "$(ROUTEHARBOR_SOURCE)/cmd" "$(ROUTEHARBOR_SOURCE)/internal" $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	@test -n "$(filter $(ROUTEHARBOR_GOARCH),$(ROUTEHARBOR_SUPPORTED_GOARCH))" || { echo "Unsupported Go target: $(ARCH)" >&2; exit 1; }
	mkdir -p $(PKG_BUILD_DIR)/bin
	cd $(PKG_BUILD_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=$(ROUTEHARBOR_GOARCH) GOARM=$(ROUTEHARBOR_GOARM) GOMIPS=softfloat GOMIPS64=softfloat GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=$(PKG_BUILD_DIR)/.gocache "$(ROUTEHARBOR_GO)" build -trimpath -buildvcs=false -ldflags='-s -w -buildid= -X main.version=$(PKG_VERSION)' -o bin/routeharbor ./cmd/routeharbor
	cd $(PKG_BUILD_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=$(ROUTEHARBOR_GOARCH) GOARM=$(ROUTEHARBOR_GOARM) GOMIPS=softfloat GOMIPS64=softfloat GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=$(PKG_BUILD_DIR)/.gocache "$(ROUTEHARBOR_GO)" build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o bin/routeharbor-helper ./cmd/routeharbor-helper
	cd $(PKG_BUILD_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=$(ROUTEHARBOR_GOARCH) GOARM=$(ROUTEHARBOR_GOARM) GOMIPS=softfloat GOMIPS64=softfloat GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=$(PKG_BUILD_DIR)/.gocache "$(ROUTEHARBOR_GO)" build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o bin/routeharbor-node ./cmd/routeharbor-node
	cd $(PKG_BUILD_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=$(ROUTEHARBOR_GOARCH) GOARM=$(ROUTEHARBOR_GOARM) GOMIPS=softfloat GOMIPS64=softfloat GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=$(PKG_BUILD_DIR)/.gocache "$(ROUTEHARBOR_GO)" build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o bin/routeharbor-continuity ./cmd/routeharbor-continuity
endef

define Package/routeharbor-guard/install
	$(INSTALL_DIR) $(1)/usr/libexec $(1)/etc/init.d $(1)/etc/routeharbor-helper $(1)/etc/routeharbor-maintenance $(1)/usr/share/nftables.d/ruleset-pre
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/routeharbor-helper $(1)/usr/libexec/
	$(INSTALL_BIN) ./files/routeharbor-guard.init $(1)/etc/init.d/routeharbor-guard
	$(INSTALL_DATA) ./files/guard.nft $(1)/etc/routeharbor-helper/guard.nft
	chmod 0700 $(1)/etc/routeharbor-helper
	chmod 0700 $(1)/etc/routeharbor-maintenance
	chmod 0600 $(1)/etc/routeharbor-helper/guard.nft
	$(INSTALL_DATA) ./files/90-routeharbor-guard.nft $(1)/usr/share/nftables.d/ruleset-pre/
endef

define Package/routeharbor/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/routeharbor $(1)/usr/bin/
	$(INSTALL_BIN) ./files/routeharbor.init $(1)/etc/init.d/routeharbor
	$(INSTALL_CONF) ./files/routeharbor.config $(1)/etc/config/routeharbor
	$(INSTALL_BIN) ./files/routeharbor-setup $(1)/usr/libexec/routeharbor-setup
endef

define Package/routeharbor-node/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/routeharbor-node $(1)/usr/bin/
	$(INSTALL_BIN) ./files/routeharbor-node.init $(1)/etc/init.d/routeharbor-node
	$(INSTALL_BIN) ./files/routeharbor-node-helper.init $(1)/etc/init.d/routeharbor-node-helper
	$(INSTALL_CONF) ./files/routeharbor-node.config $(1)/etc/config/routeharbor-node
	$(INSTALL_BIN) ./files/routeharbor-node-setup $(1)/usr/libexec/routeharbor-node-setup
endef

define Package/routeharbor-continuity/install
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/routeharbor-continuity $(1)/usr/libexec/
endef

define Package/routeharbor-conntrack/install
	true
endef

define Package/routeharbor-sing-box/install
	true
endef

define Package/routeharbor-xray/install
	true
endef

define Package/routeharbor/conffiles
/etc/config/routeharbor
/etc/routeharbor/
endef

define Package/routeharbor-guard/conffiles
/etc/routeharbor-helper/
/etc/routeharbor-maintenance/
endef

define Package/routeharbor-node/conffiles
/etc/config/routeharbor-node
/etc/routeharbor-node/
/etc/routeharbor-node-helper/
endef

define Package/routeharbor-guard/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
# An upgrade retains the guard package and its conffiles; it still stops guarded.
[ "$$PKG_UPGRADE" = "1" ] && exit 0
/usr/libexec/routeharbor-helper can-remove --state-dir /etc/routeharbor-helper || {
 echo "RouteHarbor still protects traffic. Keep routeharbor-guard installed, or explicitly run decommission --policy restore-direct." >&2
 exit 1
}
endef

$(eval $(call BuildPackage,routeharbor-guard))
$(eval $(call BuildPackage,routeharbor))
$(eval $(call BuildPackage,routeharbor-node))
$(eval $(call BuildPackage,routeharbor-sing-box))
$(eval $(call BuildPackage,routeharbor-xray))

$(eval $(call BuildPackage,routeharbor-conntrack))

$(eval $(call BuildPackage,routeharbor-continuity))
