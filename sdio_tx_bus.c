typedef struct dhd_bus {
	dhd_pub_t	*dhd;

	bcmsdh_info_t	*sdh;			/* Handle for BCMSDH calls */
	si_t		*sih;			/* Handle for SI calls */
	char		*vars;			/* Variables (from CIS and/or other) */
	uint		varsz;			/* Size of variables buffer */
	uint32		sbaddr;			/* Current SB window pointer (-1, invalid) */

	sdpcmd_regs_t	*regs;			/* Registers for SDIO core */
	uint		sdpcmrev;		/* SDIO core revision */
	uint		armrev;			/* CPU core revision */
	uint		ramrev;			/* SOCRAM core revision */
	uint32		ramsize;		/* Size of RAM in SOCRAM (bytes) */
	uint32		orig_ramsize;		/* Size of RAM in SOCRAM (bytes) */
	uint32		srmemsize;		/* Size of SRMEM */

	uint32		bus;			/* gSPI or SDIO bus */
	uint32		hostintmask;		/* Copy of Host Interrupt Mask */
	uint32		intstatus;		/* Intstatus bits (events) pending */
	bool		dpc_sched;		/* Indicates DPC schedule (intrpt rcvd) */
	bool		fcstate;		/* State of dongle flow-control */

	uint16		cl_devid;		/* cached devid for dhdsdio_probe_attach() */
	char		*fw_path;		/* module_param: path to firmware image */
	char		*nv_path;		/* module_param: path to nvram vars file */
	const char      *nvram_params;		/* user specified nvram params. */

	uint		blocksize;		/* Block size of SDIO transfers */
	uint		roundup;		/* Max roundup limit */

	struct pktq	txq;			/* Queue length used for flow-control */
	uint8		flowcontrol;		/* per prio flow control bitmask */
	uint8		tx_seq;			/* Transmit sequence number (next) */
	uint8		tx_max;			/* Maximum transmit sequence allowed */

	uint8		hdrbuf[MAX_HDR_READ + DHD_SDALIGN];
	uint8		*rxhdr;			/* Header of current rx frame (in hdrbuf) */
	uint16		nextlen;		/* Next Read Len from last header */
	uint8		rx_seq;			/* Receive sequence number (expected) */
	bool		rxskip;			/* Skip receive (awaiting NAK ACK) */

	void		*glomd;			/* Packet containing glomming descriptor */
	void		*glom;			/* Packet chain for glommed superframe */
	uint		glomerr;		/* Glom packet read errors */

	uint8		*rxbuf;			/* Buffer for receiving control packets */
	uint		rxblen;			/* Allocated length of rxbuf */
	uint8		*rxctl;			/* Aligned pointer into rxbuf */
	uint8		*databuf;		/* Buffer for receiving big glom packet */
	uint8		*dataptr;		/* Aligned pointer into databuf */
	uint		rxlen;			/* Length of valid data in buffer */

	uint8		sdpcm_ver;		/* Bus protocol reported by dongle */

	bool		intr;			/* Use interrupts */
	bool		poll;			/* Use polling */
	bool		ipend;			/* Device interrupt is pending */
	bool		intdis;			/* Interrupts disabled by isr */
	uint 		intrcount;		/* Count of device interrupt callbacks */
	uint		lastintrs;		/* Count as of last watchdog timer */
	uint		spurious;		/* Count of spurious interrupts */
	uint		pollrate;		/* Ticks between device polls */
	uint		polltick;		/* Tick counter */
	uint		pollcnt;		/* Count of active polls */

#ifdef DHD_DEBUG
	dhd_console_t	console;		/* Console output polling support */
	uint		console_addr;		/* Console address from shared struct */
#endif /* DHD_DEBUG */

	uint		regfails;		/* Count of R_REG/W_REG failures */

	uint		clkstate;		/* State of sd and backplane clock(s) */
	bool		activity;		/* Activity flag for clock down */
	int32		idletime;		/* Control for activity timeout */
	int32		idlecount;		/* Activity timeout counter */
	int32		idleclock;		/* How to set bus driver when idle */
	int32		sd_divisor;		/* Speed control to bus driver */
	int32		sd_mode;		/* Mode control to bus driver */
	int32		sd_rxchain;		/* If bcmsdh api accepts PKT chains */
	bool		use_rxchain;		/* If dhd should use PKT chains */
	bool		sleeping;		/* Is SDIO bus sleeping? */
	uint		rxflow_mode;		/* Rx flow control mode */
	bool		rxflow;			/* Is rx flow control on */
	uint		prev_rxlim_hit;		/* Is prev rx limit exceeded (per dpc schedule) */
	bool		alp_only;		/* Don't use HT clock (ALP only) */
	/* Field to decide if rx of control frames happen in rxbuf or lb-pool */
	bool		usebufpool;

#ifdef SDTEST
	/* external loopback */
	bool		ext_loop;
	uint8		loopid;

	/* pktgen configuration */
	uint		pktgen_freq;		/* Ticks between bursts */
	uint		pktgen_count;		/* Packets to send each burst */
	uint		pktgen_print;		/* Bursts between count displays */
	uint		pktgen_total;		/* Stop after this many */
	uint		pktgen_minlen;		/* Minimum packet data len */
	uint		pktgen_maxlen;		/* Maximum packet data len */
	uint		pktgen_mode;		/* Configured mode: tx, rx, or echo */
	uint		pktgen_stop;		/* Number of tx failures causing stop */

	/* active pktgen fields */
	uint		pktgen_tick;		/* Tick counter for bursts */
	uint		pktgen_ptick;		/* Burst counter for printing */
	uint		pktgen_sent;		/* Number of test packets generated */
	uint		pktgen_rcvd;		/* Number of test packets received */
	uint		pktgen_prev_time;	/* Time at which previous stats where printed */
	uint		pktgen_prev_sent;	/* Number of test packets generated when
						 * previous stats were printed
						 */
	uint		pktgen_prev_rcvd;	/* Number of test packets received when
						 * previous stats were printed
						 */
	uint		pktgen_fail;		/* Number of failed send attempts */
	uint16		pktgen_len;		/* Length of next packet to send */
#define PKTGEN_RCV_IDLE     (0)
#define PKTGEN_RCV_ONGOING  (1)
	uint16		pktgen_rcv_state;		/* receive state */
	uint		pktgen_rcvd_rcvsession;	/* test pkts rcvd per rcv session. */
#endif /* SDTEST */

	/* Some additional counters */
	uint		tx_sderrs;		/* Count of tx attempts with sd errors */
	uint		fcqueued;		/* Tx packets that got queued */
	uint		rxrtx;			/* Count of rtx requests (NAK to dongle) */
	uint		rx_toolong;		/* Receive frames too long to receive */
	uint		rxc_errors;		/* SDIO errors when reading control frames */
	uint		rx_hdrfail;		/* SDIO errors on header reads */
	uint		rx_badhdr;		/* Bad received headers (roosync?) */
	uint		rx_badseq;		/* Mismatched rx sequence number */
	uint		fc_rcvd;		/* Number of flow-control events received */
	uint		fc_xoff;		/* Number which turned on flow-control */
	uint		fc_xon;			/* Number which turned off flow-control */
	uint		rxglomfail;		/* Failed deglom attempts */
	uint		rxglomframes;		/* Number of glom frames (superframes) */
	uint		rxglompkts;		/* Number of packets from glom frames */
	uint		f2rxhdrs;		/* Number of header reads */
	uint		f2rxdata;		/* Number of frame data reads */
	uint		f2txdata;		/* Number of f2 frame writes */
	uint		f1regdata;		/* Number of f1 register accesses */
#ifdef BCMSPI
	bool		dwordmode;
#endif /* BCMSPI */

	uint8		*ctrl_frame_buf;
	uint32		ctrl_frame_len;
	bool		ctrl_frame_stat;
#ifndef BCMSPI
	uint32		rxint_mode;	/* rx interrupt mode */
#endif /* BCMSPI */
	bool		remap;		/* Contiguous 1MB RAM: 512K socram + 512K devram
					 * Available with socram rev 16
					 * Remap region not DMA-able
					 */
	bool		kso;
	bool		_slpauto;
	bool		_oobwakeup;
	bool		_srenab;
	bool        readframes;
	bool        reqbussleep;
	uint32		resetinstr;
	uint32		dongle_ram_base;
#ifdef BCMSDIOH_TXGLOM
	void		*glom_pkt_arr[SDPCM_MAXGLOM_SIZE];	/* Array of pkts for glomming */
	uint16		glom_cnt;	/* Number of pkts in the glom array */
	uint16		glom_total_len;	/* Total length of pkts in glom array */
	bool		glom_enable;	/* Flag to indicate whether tx glom is enabled/disabled */
	uint8		glom_mode;	/* Glom mode - 0-copy mode, 1 - Multi-descriptor mode */
	uint32		glomsize;	/* Glom size limitation */
#endif
} dhd_bus_t;

int dhd_bus_txctl(struct dhd_bus *bus, uchar *msg, uint msglen){
	uint8 *frame;
	uint16 len;
	uint32 swheader;
	uint retries = 0;
	bcmsdh_info_t *sdh = bus->sdh;
	uint8 doff = 0;
	int ret = -1;
	int i;

	if (bus->dhd->dongle_reset)
		return -EIO;

	/* Back the pointer to make a room for bus header */
	frame = msg - SDPCM_HDRLEN;
	len = (msglen += SDPCM_HDRLEN);

	/* Add alignment padding (optional for ctl frames) */
	if (dhd_alignctl) {
		if ((doff = ((uintptr)frame % DHD_SDALIGN))) {
			frame -= doff;
			len += doff;
			msglen += doff;
			bzero(frame, doff + SDPCM_HDRLEN);
		}
	}
	doff += SDPCM_HDRLEN;

#ifndef BCMSPI
	/* Round send length to next SDIO block */
	if (bus->roundup && bus->blocksize && (len > bus->blocksize)) {
		uint16 pad = bus->blocksize - (len % bus->blocksize);
		if ((pad <= bus->roundup) && (pad < bus->blocksize))
			len += pad;
	} else if (len % DHD_SDALIGN) {
		len += DHD_SDALIGN - (len % DHD_SDALIGN);
	}
#endif /* BCMSPI */

	/* Satisfy length-alignment requirements */
	if (forcealign && (len & (ALIGNMENT - 1)))
		len = ROUNDUP(len, ALIGNMENT);

	ASSERT(ISALIGNED((uintptr)frame, 2));


	/* Need to lock here to protect txseq and SDIO tx calls */
	dhd_os_sdlock(bus->dhd);

	BUS_WAKE(bus);

	/* Make sure backplane clock is on */
	dhdsdio_clkctl(bus, CLK_AVAIL, FALSE);

	/* Hardware tag: 2 byte len followed by 2 byte ~len check (all LE) */
	*(uint16*)frame = htol16((uint16)msglen);
	*(((uint16*)frame) + 1) = htol16(~msglen);

#ifdef BCMSDIOH_TXGLOM
	if (bus->glom_enable) {
		uint32 hwheader1, hwheader2;
		/* Software tag: channel, sequence number, data offset */
		swheader = ((SDPCM_CONTROL_CHANNEL << SDPCM_CHANNEL_SHIFT) & SDPCM_CHANNEL_MASK) | bus->tx_seq | ((doff << SDPCM_DOFFSET_SHIFT) & SDPCM_DOFFSET_MASK);
		htol32_ua_store(swheader, frame + SDPCM_FRAMETAG_LEN + SDPCM_HWEXT_LEN);
		htol32_ua_store(0, frame + SDPCM_FRAMETAG_LEN + SDPCM_HWEXT_LEN + sizeof(swheader));

		hwheader1 = (msglen - SDPCM_FRAMETAG_LEN) | (1 << 24);
		hwheader2 = (len - (msglen)) << 16;
		htol32_ua_store(hwheader1, frame + SDPCM_FRAMETAG_LEN);
		htol32_ua_store(hwheader2, frame + SDPCM_FRAMETAG_LEN + 4);

		*(uint16*)frame = htol16(len);
		*(((uint16*)frame) + 1) = htol16(~(len));
	} else
#endif /* BCMSDIOH_TXGLOM */
	{
	/* Software tag: channel, sequence number, data offset */
	swheader = ((SDPCM_CONTROL_CHANNEL << SDPCM_CHANNEL_SHIFT) & SDPCM_CHANNEL_MASK) | bus->tx_seq | ((doff << SDPCM_DOFFSET_SHIFT) & SDPCM_DOFFSET_MASK);
	htol32_ua_store(swheader, frame + SDPCM_FRAMETAG_LEN);
	htol32_ua_store(0, frame + SDPCM_FRAMETAG_LEN + sizeof(swheader));
	}
	if (!TXCTLOK(bus)) {
		bus->ctrl_frame_stat = TRUE;
		/* Send from dpc */
		bus->ctrl_frame_buf = frame;
		bus->ctrl_frame_len = len;

		if (!bus->dpc_sched) {
			bus->dpc_sched = TRUE;
			dhd_sched_dpc(bus->dhd);
		}
		if (bus->ctrl_frame_stat) {
			dhd_wait_for_event(bus->dhd, &bus->ctrl_frame_stat);
		}

		if (bus->ctrl_frame_stat == FALSE) {
			ret = 0;
		} else {
			bus->dhd->txcnt_timeout++;
			if (!bus->dhd->hang_was_sent) {
#ifdef CUSTOMER_HW4
				uint32 status, retry = 0;
				R_SDREG(status, &bus->regs->intstatus, retry);
#endif /* CUSTOMER_HW4 */
			}
			ret = -1;
			bus->ctrl_frame_stat = FALSE;
			goto done;
		}
	}

	bus->dhd->txcnt_timeout = 0;

	if (ret == -1) {
#ifdef DHD_DEBUG
		if (DHD_BYTES_ON() && DHD_CTL_ON()) {
			prhex("Tx Frame", frame, len);
		} else if (DHD_HDRS_ON()) {
			prhex("TxHdr", frame, MIN(len, 16));
		}
#endif

		do {
			ret = dhd_bcmsdh_send_buf(bus, bcmsdh_cur_sbwad(sdh), SDIO_FUNC_2, F2SYNC, frame, len, NULL, NULL, NULL);
			ASSERT(ret != BCME_PENDING);

			if (ret == BCME_NODEVICE) {

			} else if (ret < 0) {
			/* On failure, abort the command and terminate the frame */
				bus->tx_sderrs++;

				bcmsdh_abort(sdh, SDIO_FUNC_2);

#ifdef BCMSPI
#endif /* BCMSPI */
				bcmsdh_cfg_write(sdh, SDIO_FUNC_1, SBSDIO_FUNC1_FRAMECTRL,
				                 SFC_WF_TERM, NULL);
				bus->f1regdata++;

				for (i = 0; i < 3; i++) {
					uint8 hi, lo;
					hi = bcmsdh_cfg_read(sdh, SDIO_FUNC_1, SBSDIO_FUNC1_WFRAMEBCHI, NULL);
					lo = bcmsdh_cfg_read(sdh, SDIO_FUNC_1, SBSDIO_FUNC1_WFRAMEBCLO, NULL);
					bus->f1regdata += 2;
					if ((hi == 0) && (lo == 0))
						break;
				}
			}
			if (ret == 0) {
				bus->tx_seq = (bus->tx_seq + 1) % SDPCM_SEQUENCE_WRAP;
			}
		} while ((ret < 0) && retries++ < TXRETRIES);
	}

done:
	if ((bus->idletime == DHD_IDLE_IMMEDIATE) && !bus->dpc_sched) {
		bus->activity = FALSE;
		dhdsdio_clkctl(bus, CLK_NONE, TRUE);
	}

	dhd_os_sdunlock(bus->dhd);

	if (ret)
		bus->dhd->tx_ctlerrs++;
	else
		bus->dhd->tx_ctlpkts++;

	if (bus->dhd->txcnt_timeout >= MAX_CNTL_TIMEOUT)
		return -ETIMEDOUT;

	return ret ? -EIO : 0;
}

sdioh_request_byte(sdioh_info_t *sd, uint rw, uint func, uint regaddr, uint8 *byte)
{
	int err_ret;
#if defined(MMC_SDIO_ABORT)
	int sdio_abort_retry = MMC_SDIO_ABORT_RETRY_LIMIT;
#endif
	sd_info(("%s: rw=%d, func=%d, addr=0x%05x\n", __FUNCTION__, rw, func, regaddr));

	DHD_PM_RESUME_WAIT(sdioh_request_byte_wait);
	DHD_PM_RESUME_RETURN_ERROR(SDIOH_API_RC_FAIL);
	if(rw) { /* CMD52 Write */
		if (func == 0) {
			/* Can only directly write to some F0 registers.  Handle F2 enable
			 * as a special case.
			 */
			if (regaddr == SDIOD_CCCR_IOEN) {
				if (gInstance->func[2]) {
					sdio_claim_host(gInstance->func[2]);
					if (*byte & SDIO_FUNC_ENABLE_2) {
						/* Enable Function 2 */
						err_ret = sdio_enable_func(gInstance->func[2]);
						if (err_ret) {
							sd_err(("bcmsdh_sdmmc: enable F2 failed:%d",
								err_ret));
						}
					} else {
						/* Disable Function 2 */
						err_ret = sdio_disable_func(gInstance->func[2]);
						if (err_ret) {
							sd_err(("bcmsdh_sdmmc: Disab F2 failed:%d",
								err_ret));
						}
					}
					sdio_release_host(gInstance->func[2]);
				}
			}
#if defined(MMC_SDIO_ABORT)
			/* to allow abort command through F1 */
			else if (regaddr == SDIOD_CCCR_IOABORT) {
				/* Because of SDIO3.0 host issue on Manta,
				  * sometimes the abort fails.
				  * Retrying again will fix this issue.
				  */
				while (sdio_abort_retry--) {
					if (gInstance->func[func]) {
						sdio_claim_host(gInstance->func[func]);
						/*
						* this sdio_f0_writeb() can be replaced with
						* another api depending upon MMC driver change.
						* As of this time, this is temporaray one
						*/
						sdio_writeb(gInstance->func[func],
							*byte, regaddr, &err_ret);
						sdio_release_host(gInstance->func[func]);
					}
					if (!err_ret)
						break;
				}
			}
#endif /* MMC_SDIO_ABORT */
			else if (regaddr < 0xF0) {
				sd_err(("bcmsdh_sdmmc: F0 Wr:0x%02x: write disallowed\n", regaddr));
			} else {
				/* Claim host controller, perform F0 write, and release */
				if (gInstance->func[func]) {
					sdio_claim_host(gInstance->func[func]);
					sdio_f0_writeb(gInstance->func[func],
						*byte, regaddr, &err_ret);
					sdio_release_host(gInstance->func[func]);
				}
			}
		} else {
			/* Claim host controller, perform Fn write, and release */
			if (gInstance->func[func]) {
				sdio_claim_host(gInstance->func[func]);
				sdio_writeb(gInstance->func[func], *byte, regaddr, &err_ret);
				sdio_release_host(gInstance->func[func]);
			}
		}
	} else { /* CMD52 Read */
		/* Claim host controller, perform Fn read, and release */
		if (gInstance->func[func]) {
			sdio_claim_host(gInstance->func[func]);
			if (func == 0) {
				*byte = sdio_f0_readb(gInstance->func[func], regaddr, &err_ret);
			} else {
				*byte = sdio_readb(gInstance->func[func], regaddr, &err_ret);
			}
			sdio_release_host(gInstance->func[func]);
		}
	}

	if (err_ret) {
		sd_err(("bcmsdh_sdmmc: Failed to %s byte F%d:@0x%05x=%02x, Err: %d\n",
		                        rw ? "Write" : "Read", func, regaddr, *byte, err_ret));
	}

	return ((err_ret == 0) ? SDIOH_API_RC_SUCCESS : SDIOH_API_RC_FAIL);
}

