LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                                      \
                  BandwidthController.cpp              \
                  ClatdController.cpp                  \
                  CommandListener.cpp                  \
                  DnsProxyListener.cpp                 \
                  FirewallController.cpp               \
                  IdletimerController.cpp              \
                  InterfaceController.cpp              \
                  MDnsSdListener.cpp                   \
                  NatController.cpp                    \
                  NetdCommand.cpp                      \
                  NetdConstants.cpp                    \
                  NetlinkHandler.cpp                   \
                  NetlinkManager.cpp                   \
                  PppController.cpp                    \
                  ResolverController.cpp               \
                  SecondaryTableController.cpp         \
                  SoftapController_rtl.cpp	       	   \
                  TetherController.cpp                 \
                  oem_iptables_hook.cpp                \
                  UidMarkMap.cpp                       \
                  main.cpp                             \

ifeq ($(strip $(FORCE_WIFI_WORK_AS_ANDROID4_2)), true)
LOCAL_SRC_FILES += SoftapController_mt5931.cpp
endif

LOCAL_MODULE:= netd

LOCAL_C_INCLUDES := $(KERNEL_HEADERS) \
                    external/mdnsresponder/mDNSShared \
                    external/openssl/include \
                    external/stlport/stlport \
                    bionic \
                    bionic/libc/private \
                    $(call include-path-for, libhardware_legacy)/hardware_legacy

LOCAL_CFLAGS := -Werror=format

 

ifeq ($(BOARD_WLAN_DEVICE), mtk)
LOCAL_CFLAGS += -DCONFIG_P2P_AUTO_GO_AS_SOFTAP
endif

ifeq ($(BOARD_WLAN_DEVICE), mtk)
LOCAL_SRC_FILES += SoftapController_mt7601.cpp
else 
LOCAL_SRC_FILES += SoftapController.cpp
endif



ifeq ($(strip $(FORCE_WIFI_WORK_AS_ANDROID4_2)), true)
LOCAL_CFLAGS += -DFORCE_WIFI_ANDROID4_2
endif

ifeq ($(strip $(BOARD_WIFI_VENDOR)), Espressif)
LOCAL_CFLAGS += -DWIFI_CHIP_TYPE_ESP8089
endif
LOCAL_SHARED_LIBRARIES := libstlport libsysutils liblog libcutils libnetutils \
                          libcrypto libhardware_legacy libmdnssd libdl \
                          liblogwrap

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:=          \
                  ndc.c \

LOCAL_MODULE:= ndc

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)
