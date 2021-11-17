int
dhd_bus_txctl(struct dhd_bus *bus, uchar *msg, uint msglen)
{
	uint8 *frame;
	uint16 len;
	uint32 swheader;
	uint retries = 0;
	bcmsdh_info_t *sdh = bus->sdh;
	uint8 doff = 0;
	int ret = -1;
	int i;

	DHD_TRACE(("%s: Enter\n", __FUNCTION__));

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
		ASSERT(doff < DHD_SDALIGN);
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
		swheader = ((SDPCM_CONTROL_CHANNEL << SDPCM_CHANNEL_SHIFT) & SDPCM_CHANNEL_MASK)
				| bus->tx_seq
				| ((doff << SDPCM_DOFFSET_SHIFT) & SDPCM_DOFFSET_MASK);
		htol32_ua_store(swheader, frame + SDPCM_FRAMETAG_LEN + SDPCM_HWEXT_LEN);
		htol32_ua_store(0, frame + SDPCM_FRAMETAG_LEN
			+ SDPCM_HWEXT_LEN + sizeof(swheader));

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
	swheader = ((SDPCM_CONTROL_CHANNEL << SDPCM_CHANNEL_SHIFT) & SDPCM_CHANNEL_MASK)
	        | bus->tx_seq | ((doff << SDPCM_DOFFSET_SHIFT) & SDPCM_DOFFSET_MASK);
	htol32_ua_store(swheader, frame + SDPCM_FRAMETAG_LEN);
	htol32_ua_store(0, frame + SDPCM_FRAMETAG_LEN + sizeof(swheader));
	}
	if (!TXCTLOK(bus)) {
		DHD_INFO(("%s: No bus credit bus->tx_max %d, bus->tx_seq %d\n",
			__FUNCTION__, bus->tx_max, bus->tx_seq));
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
			DHD_INFO(("%s: ctrl_frame_stat == FALSE\n", __FUNCTION__));
			ret = 0;
		} else {
			bus->dhd->txcnt_timeout++;
			if (!bus->dhd->hang_was_sent) {
#ifdef CUSTOMER_HW4
				uint32 status, retry = 0;
				R_SDREG(status, &bus->regs->intstatus, retry);
				DHD_TRACE_HW4(("%s: txcnt_timeout, INT status=0x%08X\n",
					__FUNCTION__, status));
				DHD_TRACE_HW4(("%s : tx_max : %d, tx_seq : %d, clkstate : %d \n",
					__FUNCTION__, bus->tx_max, bus->tx_seq, bus->clkstate));
#endif /* CUSTOMER_HW4 */
				DHD_ERROR(("%s: ctrl_frame_stat == TRUE txcnt_timeout=%d\n",
					__FUNCTION__, bus->dhd->txcnt_timeout));
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
			ret = dhd_bcmsdh_send_buf(bus, bcmsdh_cur_sbwad(sdh), SDIO_FUNC_2, F2SYNC,
			                          frame, len, NULL, NULL, NULL);
			ASSERT(ret != BCME_PENDING);

			if (ret == BCME_NODEVICE) {
				DHD_ERROR(("%s: Device asleep already\n", __FUNCTION__));
			} else if (ret < 0) {
			/* On failure, abort the command and terminate the frame */
				DHD_INFO(("%s: sdio error %d, abort command and terminate frame.\n",
				          __FUNCTION__, ret));
				bus->tx_sderrs++;

				bcmsdh_abort(sdh, SDIO_FUNC_2);

#ifdef BCMSPI
				DHD_ERROR(("%s: Check Overflow or F2-fifo-not-ready counters."
					   " gSPI transmit error on control channel.\n",
					   __FUNCTION__));
#endif /* BCMSPI */
				bcmsdh_cfg_write(sdh, SDIO_FUNC_1, SBSDIO_FUNC1_FRAMECTRL,
				                 SFC_WF_TERM, NULL);
				bus->f1regdata++;

				for (i = 0; i < 3; i++) {
					uint8 hi, lo;
					hi = bcmsdh_cfg_read(sdh, SDIO_FUNC_1,
					                     SBSDIO_FUNC1_WFRAMEBCHI, NULL);
					lo = bcmsdh_cfg_read(sdh, SDIO_FUNC_1,
					                     SBSDIO_FUNC1_WFRAMEBCLO, NULL);
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
