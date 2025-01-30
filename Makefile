include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=gryphon-kernel-module-pc
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define KernelPackage/gryphon-kernel-module-pc
	SUBMENU:=Other modules
	TITLE:=gryphon-kernel-module-pc Kernel Modules
	FILES:=$(PKG_BUILD_DIR)/gryphon.ko
endef

define KernelPackage/gryphon-kernel-module-pc/description
	gryphon-kernel-module-pc Kernel Modules
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(LINUX_DIR) ARCH="$(LINUX_KARCH)" CROSS_COMPILE="$(TARGET_CROSS)" SUBDIRS="$(PKG_BUILD_DIR)" M="$(PKG_BUILD_DIR)"  modules
endef

define Package/gryphon-kernel-module-pc/install
	$(INSTALL_DIR) $(1)/etc/modules.d/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/99-gryphon-kernel-module-pc $(1)/etc/modules.d/

endef

$(eval $(call KernelPackage,gryphon-kernel-module-pc))
