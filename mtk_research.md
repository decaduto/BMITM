```
1|camellian:/proc # zcat config.gz | grep -i wifi                                                                                                                   
CONFIG_MTK_COMBO_WIFI=y
CONFIG_MTK_WIFI_MCC_SUPPORT=y
CONFIG_MTK_DHCPV6C_WIFI=y
CONFIG_MTK_MCIF_WIFI_SUPPORT=y
# CONFIG_MWIFIEX is not set
# CONFIG_VIRT_WIFI is not set
```

(1) CONFIG_MTK_COMBO_WIFI: abilita il wifi mediatek

(2) CONFIG_MTK_WIFI_MCC_SUPPORT:  [if it is set to TRUE, wlan will support Multi-Channel Concurrency, otherwise, only support Single Channel Concurrency](https://android.googlesource.com/kernel/mediatek/+/android-mtk-3.18/drivers/misc/mediatek/connectivity/Kconfig#241) Not interesting

(3) CONFIG_MTK_DHCPV6C_WIFI: probably enable DHCP version 6, not interesting for now.

(4) CONFIG_MTK_MCIF_WIFI_SUPPORT: [This config is used to enable or disable connection between Mediatek Modem WiFi Service and Mediatek WiFi dirver, so applications in Modem can send/receive IP packets to/from WiFi coprocessor through MCIF directly.](https://github.com/sameri2010/XiaomiRedmiNote10S_kernelOpenSource/blob/7094834e4fca19af2ca43a752debf95c0022b949/drivers/misc/mediatek/mddp/Kconfig#L9)
^ estremamente interessante, è una sorta di RAM sharing ma inteso per i frame broadcast, amplia notevolmente la superficie di exploitation,

il codice lato Baseband è noto per essere più complesso di quello WIFI, compromettere il modem significa compromettere anche il chip wifi e vice versa,

inoltre, a differenza del bluetoot, il baseband è SEMPRE acceso e ha un raggio molto più grande rispetto a quello del bluetooth, l'unico svantaggio è che lato HW potrebbe richiedere

una SDR Tx per poter emulare una BSS.

Da notare che sotto (4) nel link, c'è anche questo: 
```

config MTK_MDDP_WH_SUPPORT
	bool "Support Mediatek MD Direct Path WiFi Hotspot"
	depends on MTK_MCIF_WIFI_SUPPORT
	help
	  This config is used to enable or disable WiFi Hotspot
	  through MCIF. When config is enabled, tethering traffic
	  can be transferred between Modem and WiFi coprocessor
	  directly instead of crossing application processor
	  all the time.
```

^ ripete quello scritto sopra, abbiamo codice Hotspot (pieno di parsing) che funge da possibile surface.

Log di Iw list:

```
	Supported commands:
		 * new_interface
		 * set_interface
		 * new_key
		 * start_ap
		 * new_station
		 * set_bss
		 * associate
		 * deauthenticate
		 * disassociate
		 * join_ibss
		 * set_pmksa
		 * del_pmksa
		 * flush_pmksa
		 * remain_on_channel
		 * set_tx_bitrate_mask
		 * frame
		 * frame_wait_cancel
		 * set_channel
		 * tdls_mgmt
		 * tdls_oper
		 * start_sched_scan
		 * testmode
		 * connect
		 * disconnect
		 * channel_switch
	Supported TX frame types:
		 * IBSS: 0x00 0x10 0x20 0x30 0x40 0x50 0x60 0x70 0x80 0x90 0xa0 0xb0 0xc0 0xd0 0xe0 0xf0
		 * managed: 0x00 0x10 0x20 0x30 0x40 0x50 0x60 0x70 0x80 0x90 0xa0 0xb0 0xc0 0xd0 0xe0 0xf0
		 * AP: 0x00 0x10 0x20 0x30 0x40 0x50 0x60 0x70 0x80 0x90 0xa0 0xb0 0xc0 0xd0 0xe0 0xf0
		 * AP/VLAN: 0x00 0x10 0x20 0x30 0x40 0x50 0x60 0x70 0x80 0x90 0xa0 0xb0 0xc0 0xd0 0xe0 0xf0
		 * P2P-client: 0x00 0x10 0x20 0x30 0x40 0x50 0x60 0x70 0x80 0x90 0xa0 0xb0 0xc0 0xd0 0xe0 0xf0
		 * P2P-GO: 0x00 0x10 0x20 0x30 0x40 0x50 0x60 0x70 0x80 0x90 0xa0 0xb0 0xc0 0xd0 0xe0 0xf0
	Supported RX frame types:
		 * IBSS: 0xd0
		 * managed: 0x40 0xb0 0xd0
		 * AP: 0x00 0x20 0x40 0xa0 0xb0 0xc0 0xd0
		 * AP/VLAN: 0x00 0x20 0x40 0xa0 0xb0 0xc0 0xd0
		 * P2P-client: 0x40 0xd0
		 * P2P-GO: 0x40 0xd0
	WoWLAN support:
		 * wake up on anything (device continues operating normally)
		 * wake up on disconnect
		 * wake up on magic packet
	software interface modes (can always be added):
		 * P2P-device
	valid interface combinations:
		 * #{ managed } <= 3, #{ P2P-client, P2P-GO } <= 1,
		   total <= 3, #channels <= 2
	Device has client inactivity timer.
	Device supports SAE with AUTHENTICATE command
	Device supports scan flush.
```

dump della struct wiphy, i callback in cfg80211_ops sono:

```

		 * new_interface
		 * set_interface
		 * new_key
		 * start_ap
		 * new_station
		 * set_bss
		 * associate
		 * deauthenticate
		 * disassociate
		 * join_ibss
		 * set_pmksa
		 * del_pmksa
		 * flush_pmksa
		 * remain_on_channel
		 * set_tx_bitrate_mask
		 * frame
		 * frame_wait_cancel
		 * set_channel
		 * tdls_mgmt
		 * tdls_oper
		 * start_sched_scan
		 * testmode
		 * connect
		 * disconnect
		 * channel_switch
```

Sappiamo che supporta WoWlan, ergo si potrebbe studiare un attacco Layer 2 sui Magic Frames (richiede conoscenza indirizzo MAC del target, ottenibile in più modi)

Analisi della feature CONFIG_MTK_MCIF_WIFI_SUPPORT (Modem Coexistence InterFace?)
==================================================

Non presente nel source del driver Mediatek come CONFIG_MTK_MCIF_WIFI_SUPPORT, definita come CFG_MTK_MCIF_WIFI_SUPPORT

```
/*! \file   mddp.c
*    \brief  Main routines for modem direct path handling
*
*    This file contains the support routines of modem direct path operation.
*/
```

(from /mgmt/mddp.c)

Lista delle funzioni supportate lato driver dal mddp:

```c
int32_t mddpMdNotifyInfo(struct mddpw_md_notify_info_t *prMdInfo);
int32_t mddpChangeState(enum mddp_state_e event, void *buf, uint32_t *buf_len);
int32_t mddpGetMdStats(IN struct net_device *prDev);
int32_t mddpSetTxDescTemplate(IN struct ADAPTER *prAdapter,
	IN struct STA_RECORD *prStaRec,
	IN uint8_t fgActivate);
void mddpUpdateReorderQueParm(struct ADAPTER *prAdapter, struct RX_BA_ENTRY *prReorderQueParm, struct SW_RFB *prSwRfb);
int32_t mddpNotifyDrvMac(IN struct ADAPTER *prAdapter);
int32_t mddpNotifyDrvTxd(IN struct ADAPTER *prAdapter, IN struct STA_RECORD *prStaRec, IN uint8_t fgActivate);
int32_t mddpNotifyStaTxd(IN struct ADAPTER *prAdapter);
void mddpNotifyWifiOnStart(void);
int32_t mddpNotifyWifiOnEnd(void);
void mddpNotifyWifiOffStart(void);
void mddpNotifyWifiOffEnd(void);
void setMddpSupportRegister(IN struct ADAPTER *prAdapter);
```

Per semplicità, si studiano prima le funzioni con args -> (void)

```c
void mddpNotifyWifiOnStart(void){
	mddpRegisterCb();
	mddpNotifyWifiStatus(MDDPW_DRV_INFO_WLAN_ON_START);
}

/* da cui */

static int32_t mddpRegisterCb(void)
{
	int32_t ret = 0;

	gMddpFunc.wifi_handle = &gMddpWFunc;

	ret = mddp_drv_attach(&gMddpDrvConf, &gMddpFunc);
	DBGLOG(INIT, INFO, "mddp_drv_attach ret: %d\n", ret);

	return ret;
}

/* 
nota che a quanto pare mddp è un driver A SE STANTE, infatti la funzione 'mddp_drv_attach' non è presente nel path di gen4 
MDP è un driver mediatek usato per il Media Direct Path (conversione di formati media?)
da https://github.com/OnePlusOSS/android_kernel_oneplus_mt6893/blob/b0d6703b0bcd129e65424b3cfa368dd5e0a8f4b0/drivers/misc/mediatek/mddp/Kconfig
otteniamo varie informazioni già citate sopra per la feature MDDP, nota che MTK_MDDP_WH_SUPPORT non è supportato sul redmi 10 5g, invece MTK_MDDP_SUPPORT lo è.

Path al source: https://github.com/OnePlusOSS/android_kernel_oneplus_mt6893/tree/b0d6703b0bcd129e65424b3cfa368dd5e0a8f4b0/drivers/misc/mediatek/mddp
*/


```

Analizzando il driver MDDP si incappa in funzioni come:

```c

int32_t mddpwh_sm_init(struct mddp_app_t *app){
	memcpy(&app->state_machines,
		&mddpwh_state_machines_s,
		sizeof(mddpwh_state_machines_s));

	MDDP_S_LOG(MDDP_LL_INFO,
			"%s: %p, %p\n",
			__func__,
			&(app->state_machines), &mddpwh_state_machines_s);
	mddp_dump_sm_table(app);

	app->md_recv_msg_hdlr = mddpw_wfpm_msg_hdlr;
	app->reg_drv_callback = mddpw_drv_reg_callback; /* here */
	app->dereg_drv_callback = mddpw_drv_dereg_callback;
	app->sysfs_callback = mddpwh_sysfs_callback;
	memcpy(&app->md_cfg, &mddpw_md_cfg_s, sizeof(struct mddp_md_cfg_t));
	app->is_config = 1;

	setup_timer(&mddpw_timer, mddpw_reset_work, 0);
	INIT_WORK(&(mddpw_reset_workq), mddpw_ack_md_reset);
	return 0;
}

static int32_t mddpw_drv_reg_callback(struct mddp_drv_handle_t *handle){
	struct mddpw_drv_handle_t         *wifi_handle;

	if (handle->wifi_handle == NULL) {
		MDDP_S_LOG(MDDP_LL_ERR, "%s: handle NULL\n", __func__);
		return -EINVAL;
	}

	wifi_handle = handle->wifi_handle;

	wifi_handle->add_txd = mddpw_drv_add_txd; /* here */
	wifi_handle->get_net_stat = mddpw_drv_get_net_stat;
	wifi_handle->get_ap_rx_reorder_buf = mddpw_drv_get_ap_rx_reorder_buf;
	wifi_handle->get_md_rx_reorder_buf = mddpw_drv_get_md_rx_reorder_buf;
	wifi_handle->notify_drv_info = mddpw_drv_notify_info;
	wifi_handle->get_net_stat_ext = mddpw_drv_get_net_stat_ext;
	wifi_handle->get_sys_stat = mddpw_drv_get_sys_stat;

	return 0;
}


static int32_t mddpw_drv_add_txd(struct mddpw_txd_t *txd)
{
	struct mddp_md_msg_t    *md_msg;
	struct mddp_app_t       *app;

	// Send TXD to MD
	app = mddp_get_app_inst(MDDP_APP_TYPE_WH);

	if (!app->is_config) {
		MDDP_S_LOG(MDDP_LL_ERR,
			"%s: app_type(MDDP_APP_TYPE_WH) not configured!\n",
			__func__);
		return -ENODEV;
	}

	md_msg = kzalloc(sizeof(struct mddp_md_msg_t) +
	sizeof(struct mddpw_txd_t) + txd->txd_length, GFP_ATOMIC);

	if (unlikely(!md_msg)) { // controllo del cazzo
		WARN_ON(1);
		return -ENOMEM;
	}

	md_msg->msg_id = IPC_MSG_ID_WFPM_SEND_MD_TXD_NOTIFY;
	md_msg->data_len = sizeof(struct mddpw_txd_t) + txd->txd_length; // -> txd->txd_length viene controllata?
	memcpy(md_msg->data, txd, md_msg->data_len);
	/* aka 	memcpy(md_msg->data, txd, (sizeof(struct mddpw_txd_t) + txd->txd_length));
	mddp_ipc_send_md(app, md_msg, MDFPM_USER_ID_NULL);

	return 0;
}
```

Esempio di code quality, da notare che poi `md_msg` viene inviata tramite ipc (al modem?)

