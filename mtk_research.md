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

Analisi della feature CONFIG_MTK_MCIF_WIFI_SUPPORT
==================================================

Non presente nel source del driver Mediatek,
