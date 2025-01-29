include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=gryphon-dpi-modules
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define KernelPackage/gryphon-dpi-modules
	SUBMENU:=Other modules
	TITLE:=gryphon-dpi-modules Kernel Modules
	FILES:=$(PKG_BUILD_DIR)/gryphon.ko
endef

define KernelPackage/gryphon-dpi-modules/description
	gryphon-dpi-modules Kernel Modules
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(LINUX_DIR) ARCH="$(LINUX_KARCH)" CROSS_COMPILE="$(TARGET_CROSS)" SUBDIRS="$(PKG_BUILD_DIR)" M="$(PKG_BUILD_DIR)"  modules
endef

define Package/gryphon-dpi-modules/install
	$(INSTALL_DIR) $(1)/etc/modules.d/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/99-gryphon-dpi-modules $(1)/etc/modules.d/

endef

$(eval $(call KernelPackage,gryphon-dpi-modules))
