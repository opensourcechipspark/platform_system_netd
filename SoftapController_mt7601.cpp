/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/wireless.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define LOG_TAG "SoftapController"
#include <cutils/log.h>
#include <netutils/ifc.h>
#include <private/android_filesystem_config.h>
#include "wifi.h"
#include "ResponseCode.h"

#include "SoftapController.h"
#ifdef CONFIG_P2P_AUTO_GO_AS_SOFTAP
#include <arpa/inet.h>
#endif

static const char HOSTAPD_CONF_FILE[]    = "/data/misc/wifi/hostapd.conf";
static const char HOSTAPD_BIN_FILE[]    = "/system/bin/hostapd";
#ifdef CONFIG_P2P_AUTO_GO_AS_SOFTAP
//TetherController *SoftapController::sTetherCtrl = NULL;

static const char SERVER_ADDRESS[] = "192.168.49.1";
static const char DHCP_RANGE[] = {"192.168.49"}; //192.168.49.2-192.168.49.254

#define WLAN_INTERFACE "wlan0"
#define SOFTAP_INTERFACE "p2p0"
#define SOFTAP_REAL_INTERFACE "p2p-ap0-0"
#endif

SoftapController::SoftapController()
    : mPid(0) {
#ifdef CONFIG_P2P_AUTO_GO_AS_SOFTAP
	ALOGV("SoftapController");
	mDaemonState = 0;
#if 0
    if (!sTetherCtrl)
        sTetherCtrl = new TetherController();
#endif	
	mSock = socket(AF_INET, SOCK_DGRAM, 0);
	if (mSock < 0)
		ALOGE("Failed to open socket");
	memset(mIface, 0, sizeof(mIface));
#endif
}

SoftapController::~SoftapController() {
#ifdef CONFIG_P2P_AUTO_GO_AS_SOFTAP	
    ALOGV("~SoftapController");
    if (mSock >= 0)
        close(mSock);
#endif
}

int SoftapController::startSoftap() {
    pid_t pid = 1;

    if (mPid) {
        ALOGE("SoftAP is already running");
        return ResponseCode::SoftapStatusResult;
    }
#ifdef CONFIG_P2P_AUTO_GO_AS_SOFTAP
    if (mSock < 0) {
        ALOGE("Softap startap - failed to open socket");
        return -1;
    }
    if (!mDaemonState) {
        ALOGE("Softap startap - daemon is not running");
        return -1;
    }    
	
    if (!pid) {
        ALOGE("Should never get here!");
        return -1;
    } else {
	      *mBuf = 0;
          mPid = pid;

#if 0
		  int ret = 0;
          int num_addrs = 253; //255-2
          int arg_index = 2;
          int array_index = 0;
		  char *wbuf = NULL;
	
          in_addr *addrs = (in_addr *)malloc(sizeof(in_addr) * num_addrs);
	      struct in_addr addr;
		  //Set p2p-ap0-0 ip.
		  ifc_init();	
		  
		  if (!inet_aton(SERVER_ADDRESS, &addr)) {
			   // Handle flags only case
		   } else {
			   if (ret = ifc_set_addr(SOFTAP_REAL_INTERFACE, addr.s_addr)) {
				   ALOGD("start Softap: set p2p-ap0-0 address fail, ret = %d", ret);				   
				   ifc_close();
				   return ret; 
			   }else
			       ALOGD("start Softap: set p2p-ap0-0 address success, ret = %d", ret);				   
			   
		  	   #if 0
			   // Set prefix length on a non zero address
			   if (addr.s_addr != 0 && ifc_set_prefixLength(SERVER_ADDRESS, atoi(argv[4]))) {
				  ALOGD("start Softap: set prefix length fail");
				  ifc_close();
				  return 0;
			  }
			   #endif
		   }
		  
		  ifc_close();

		  //Start Tether.
          while (array_index < num_addrs) {
		  	  asprintf(&wbuf, "%s.%d",DHCP_RANGE, arg_index++);
			  //ALOGD("wbuf : %s", wbuf);
              if (!inet_aton((const char*)wbuf, &(addrs[array_index++]))) {
                  free(addrs);
				  free(wbuf);
				  ALOGD("start Softap: get dhcp range fail");
                  return 0;
              }
			  memset(wbuf, 0, sizeof(wbuf));
          }
		  if (sTetherCtrl->isTetheringStarted())
		  {
		  	ret = sTetherCtrl->stopTethering();
            if (ret != 0)
            {
             ALOGD("start Softap: stopTethering fail");
            }			
		  }
		  
          ret = sTetherCtrl->startTethering(num_addrs, addrs);

		  if (ret != 0)
		  {
		  	 ALOGD("start Softap: startTethering fail");
		  }
#endif
           ALOGD("Softap startap - Ok");
           usleep(AP_BSS_START_DELAY);
    }
#else
    if ((pid = fork()) < 0) {
        ALOGE("fork failed (%s)", strerror(errno));
        return ResponseCode::ServiceStartFailed;
    }

    if (!pid) {
        ensure_entropy_file_exists();
        if (execl(HOSTAPD_BIN_FILE, HOSTAPD_BIN_FILE,
                  "-e", WIFI_ENTROPY_FILE,
                  HOSTAPD_CONF_FILE, (char *) NULL)) {
            ALOGE("execl failed (%s)", strerror(errno));
        }
        ALOGE("SoftAP failed to start");
        return ResponseCode::ServiceStartFailed;
    } else {
        mPid = pid;
        ALOGD("SoftAP started successfully");
        usleep(AP_BSS_START_DELAY);
    }
#endif
    return ResponseCode::SoftapStatusResult;
}

int SoftapController::stopSoftap() {
#ifdef CONFIG_P2P_AUTO_GO_AS_SOFTAP
	ALOGD("stopSoftap: %s", mIface);
	int ret = 0;
	if (mPid == 0) {
		ALOGE("Softap already stopped");
		return 0;
	}

	if (mSock < 0) {
		ALOGE("Softap stopap - failed to open socket");
		return -1;
	}
    *mBuf = 0;
    mPid = 0;
    ALOGV("Softap service stopped: %d", ret);
 
#if 0
	//Stop tether(dnsmasg)
	sTetherCtrl->stopTethering();
#endif

	ret = setConfig("P2P_GROUP_REMOVE p2p-ap0-0", NULL);
	if (ret != 0)
		ALOGV("stopSoftap P2P_GROUP_REMOVE p2p-ap0-0 fail, ret = %d", ret);
	
	stopDriver(mIface);
    usleep(AP_BSS_STOP_DELAY);
#else
    if (mPid == 0) {
        ALOGE("SoftAP is not running");
        return ResponseCode::SoftapStatusResult;
    }

    ALOGD("Stopping the SoftAP service...");
    kill(mPid, SIGTERM);
    waitpid(mPid, NULL, 0);

    mPid = 0;
    ALOGD("SoftAP stopped successfully");
    usleep(AP_BSS_STOP_DELAY);

#endif
    return ResponseCode::SoftapStatusResult;
}

bool SoftapController::isSoftapStarted() {
    return (mPid != 0);
}

#ifdef CONFIG_P2P_AUTO_GO_AS_SOFTAP
int SoftapController::startDriver(char *iface) {
    int ret = 0;

    ALOGD("startDriver: %s", iface);
    
    if (mSock < 0) {
        ALOGE("Softap driver start - failed to open socket");
        return -1;
    }
    if (!iface || (iface[0] == '\0')) {
        ALOGD("Softap driver start - wrong interface");
        iface = mIface;
    }
    if (mDaemonState == 1) {
        ALOGD("Softap startap - daemon is already running");
        return -1;
    }        

	//Init wlan0 firstly.

	ifc_init();
	ret = ifc_up(WLAN_INTERFACE);
	
	//Init p2p0
    ret = ifc_up(iface);
    ifc_close();    
    
    *mBuf = 0;
    ret = wifi_ap_start_supplicant();
    if (ret < 0) {
        ALOGE("Softap daemon start: %d", ret);
        return ret;
    }

    mDaemonState = 1;
    
    usleep(AP_DRIVER_START_DELAY);
    ALOGV("Softap daemon start: %d", ret);
    return ret;
}

int SoftapController::stopDriver(char *iface) {
    int ret;

    ALOGD("stopDriver: %s", iface);
    
    if (mSock < 0) {
        ALOGE("Softap driver stop - failed to open socket");
        return -1;
    }
    if (!iface || (iface[0] == '\0')) {
        ALOGD("Softap driver stop - wrong interface");
        iface = mIface;
    }
    *mBuf = 0;

    ifc_init();

    ret = ifc_down(iface);
	if (ret != 0)
		ALOGD("Softap driver stop - turn down %s fail\n", iface);
	//Set wlan0 down

	ret = ifc_down(SOFTAP_INTERFACE);
	if (ret != 0)
		ALOGD("Softap driver stop - turn down p2p0 fail\n");
	
	ret = ifc_down(WLAN_INTERFACE);
	if (ret != 0)
		ALOGD("Softap driver stop - turn down p2p-ap0-0 fail\n");
	
    ifc_close();
    if (ret < 0) {
        ALOGE("Softap %s down: %d", iface, ret);
    }

    ret = wifi_ap_stop_supplicant();
    
    mDaemonState = 0;
    
    ALOGV("Softap daemon stop: %d", ret);
    return ret;
}

int SoftapController::setCommand(char *iface, const char *cmd, unsigned buflen) {
    int connectTries = 0;
    unsigned replybuflen;
    int ret = 0;
    
    if (mDaemonState != 1) {
        ALOGD("setCommand - daemon is not running");
        startDriver(mIface);
    }        
    
    if (buflen == 0) {
        replybuflen = SOFTAP_MAX_BUFFER_SIZE;
    } 
    else {
        replybuflen = buflen;
    }
    
    // <1> connect to the daemon
    while (true) {
        ALOGD("try to connect to daemon");
        if (wifi_connect_to_supplicant() == 0) {
            ALOGD("connect to daemon");
            break;
        }
        //maximum delay 12s
        if (connectTries++ < 40) {
            sched_yield();
            //ALOGD("softap sleep %d us\n", AP_CONNECT_TO_DAEMON_DELAY);
            usleep(AP_CONNECT_TO_DAEMON_DELAY);
        } else {
            ALOGE("connect to daemon failed!");
            return -1;
        }
    }
       
    if (wifi_command(cmd, mBuf, &buflen) != 0) {
        ALOGE("Command failed: \"%s\"", cmd);
        ret = -1;
    }
    else {
        ALOGD("Command OK: \"%s\"", cmd);
        mBuf[buflen] = '\0';
    }
    
    wifi_close_supplicant_connection();
    
    return ret;
}
int SoftapController::setConfig(const char *cmd, const char *arg)
{
    char cmd_str[SOFTAP_MAX_BUFFER_SIZE];
    
    snprintf(cmd_str, SOFTAP_MAX_BUFFER_SIZE, "%s", cmd);
    
    return setCommand(mIface, cmd_str, 0);
}

#endif

/*
 * Arguments:
 *  argv[2] - wlan interface
 *  argv[3] - SSID
 *  argv[4] - Broadcast/Hidden
 *  argv[5] - Channel
 *  argv[6] - Security
 *  argv[7] - Key
 */
int SoftapController::setSoftap(int argc, char *argv[]) {
    char psk_str[2*SHA256_DIGEST_LENGTH+1];
    int ret = ResponseCode::SoftapStatusResult;
    int i = 0;
    int fd;
    int hidden = 0;
    int channel = AP_CHANNEL_DEFAULT;
    char *wbuf = NULL;
    char *fbuf = NULL;
#ifdef CONFIG_P2P_AUTO_GO_AS_SOFTAP	
    char *ssid, *iface;
#endif

    if (argc < 5) {
        ALOGE("Softap set is missing arguments. Please use:");
        ALOGE("softap <wlan iface> <SSID> <hidden/broadcast> <channel> <wpa2?-psk|open> <passphrase>");
        return ResponseCode::CommandSyntaxError;
    }

    if (!strcasecmp(argv[4], "hidden"))
        hidden = 1;

    if (argc >= 5) {
        channel = atoi(argv[5]);
        if (channel <= 0)
            channel = AP_CHANNEL_DEFAULT;
    }

#ifdef CONFIG_P2P_AUTO_GO_AS_SOFTAP
    if (mSock < 0) {
        ALOGE("Softap set - failed to open socket");
        return -1;
    }
    if (argc < 4) {
        ALOGE("Softap set - missing arguments");
        return -1;
    }

	strncpy(mIface, SOFTAP_INTERFACE, sizeof(mIface));
    iface = argv[2];

	/* Create command line */
	if (argc > 3) {
		ssid = argv[3];
	} else {
		ssid = (char *)"AndroidAP";
	}

    if (argc > 7) {
		asprintf(&wbuf, "ssid=%s wpapsk=%s key_mgmt=WPA-PSK pairwise=CCMP proto=WPA2",ssid, argv[7]);
        if (!strcmp(argv[6], "wpa-psk")) {
            generatePsk(argv[3], argv[7], psk_str);
			asprintf(&wbuf, "ssid=%s wpapsk=%s key_mgmt=WPA-PSK pairwise=TKIP proto=WPA",ssid, argv[7]);
        } else if (!strcmp(argv[6], "wpa2-psk")) {
            generatePsk(argv[3], argv[7], psk_str);
			asprintf(&wbuf, "ssid=%s wpapsk=%s key_mgmt=WPA-PSK pairwise=CCMP proto=WPA2",ssid, argv[7]);
        } else if (!strcmp(argv[6], "open")) {
			asprintf(&wbuf, "ssid=%s wpapsk= key_mgmt=NONE pairwise=NONE proto=WPA2",ssid);
        }
    } else if (argc > 6) {
        if (!strcmp(argv[6], "open")) {
			asprintf(&wbuf, "ssid=%s wpapsk= key_mgmt=NONE pairwise=NONE proto=WPA2",ssid);
        }
    } else {
		asprintf(&wbuf, "ssid=%s wpapsk= key_mgmt=NONE pairwise=NONE proto=WPA2",ssid);
    }

	asprintf(&fbuf, "P2P_GROUP_ADD softap %s", wbuf);
	
	ret = setConfig(fbuf, NULL);

	if (wbuf != NULL)
		free(wbuf);

	if (fbuf != NULL)
		free(fbuf);
	
	return ret;
#endif

    asprintf(&wbuf, "interface=%s\ndriver=nl80211\nctrl_interface="
            "/data/misc/wifi/hostapd\nssid=%s\nchannel=%d\nieee80211n=1\n"
            "hw_mode=g\nignore_broadcast_ssid=%d\n",
            "ap0", argv[3], channel, hidden);

    if (argc > 7) {
        if (!strcmp(argv[6], "wpa-psk")) {
            generatePsk(argv[3], argv[7], psk_str);
            asprintf(&fbuf, "%swpa=1\nwpa_pairwise=TKIP CCMP\nwpa_psk=%s\n", wbuf, psk_str);
        } else if (!strcmp(argv[6], "wpa2-psk")) {
            generatePsk(argv[3], argv[7], psk_str);
            asprintf(&fbuf, "%swpa=2\nrsn_pairwise=CCMP\nwpa_psk=%s\n", wbuf, psk_str);
        } else if (!strcmp(argv[6], "open")) {
            asprintf(&fbuf, "%s", wbuf);
        }
    } else if (argc > 6) {
        if (!strcmp(argv[6], "open")) {
            asprintf(&fbuf, "%s", wbuf);
        }
    } else {
        asprintf(&fbuf, "%s", wbuf);
    }

    fd = open(HOSTAPD_CONF_FILE, O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW, 0660);
    if (fd < 0) {
        ALOGE("Cannot update \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        free(wbuf);
        free(fbuf);
        return ResponseCode::OperationFailed;
    }
    if (write(fd, fbuf, strlen(fbuf)) < 0) {
        ALOGE("Cannot write to \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        ret = ResponseCode::OperationFailed;
    }
    free(wbuf);
    free(fbuf);

    /* Note: apparently open can fail to set permissions correctly at times */
    if (fchmod(fd, 0660) < 0) {
        ALOGE("Error changing permissions of %s to 0660: %s",
                HOSTAPD_CONF_FILE, strerror(errno));
        close(fd);
        unlink(HOSTAPD_CONF_FILE);
        return ResponseCode::OperationFailed;
    }

    if (fchown(fd, AID_SYSTEM, AID_WIFI) < 0) {
        ALOGE("Error changing group ownership of %s to %d: %s",
                HOSTAPD_CONF_FILE, AID_WIFI, strerror(errno));
        close(fd);
        unlink(HOSTAPD_CONF_FILE);
        return ResponseCode::OperationFailed;
    }

    close(fd);

    return ret;
}

/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or P2P or STA
 */
int SoftapController::fwReloadSoftap(int argc, char *argv[])
{
    int i = 0;
    char *fwpath = NULL;

    if (mSock < 0) {
        ALOGE("Softap fwrealod - failed to open socket");
        return -1;
    }

    if (argc < 4) {
        ALOGE("SoftAP fwreload is missing arguments. Please use: softap <wlan iface> <AP|P2P|STA>");
        return ResponseCode::CommandSyntaxError;
    }

    if (strcmp(argv[3], "AP") == 0) {
        fwpath = (char *)wifi_get_fw_path(WIFI_GET_FW_PATH_AP);
    } else if (strcmp(argv[3], "P2P") == 0) {
        fwpath = (char *)wifi_get_fw_path(WIFI_GET_FW_PATH_P2P);
    } else if (strcmp(argv[3], "STA") == 0) {
        fwpath = (char *)wifi_get_fw_path(WIFI_GET_FW_PATH_STA);
    }
    if (!fwpath)
        return ResponseCode::CommandParameterError;
    if (wifi_change_fw_path((const char *)fwpath)) {
        ALOGE("Softap fwReload failed");
        return ResponseCode::OperationFailed;
    }
    else {
        ALOGD("Softap fwReload - Ok");
    }
    return ResponseCode::SoftapStatusResult;
}

void SoftapController::generatePsk(char *ssid, char *passphrase, char *psk_str) {
    unsigned char psk[SHA256_DIGEST_LENGTH];
    int j;
    // Use the PKCS#5 PBKDF2 with 4096 iterations
    PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase),
            reinterpret_cast<const unsigned char *>(ssid), strlen(ssid),
            4096, SHA256_DIGEST_LENGTH, psk);
    for (j=0; j < SHA256_DIGEST_LENGTH; j++) {
        sprintf(&psk_str[j*2], "%02x", psk[j]);
    }
}
