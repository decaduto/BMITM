int ipa3_send(struct ipa3_sys_context *sys, u32 num_desc, struct ipa3_desc *desc, bool in_atomic){
	struct ipa3_tx_pkt_wrapper *tx_pkt, *tx_pkt_first = NULL;
	struct ipahal_imm_cmd_pyld *tag_pyld_ret = NULL;
	struct ipa3_tx_pkt_wrapper *next_pkt;
	struct gsi_xfer_elem gsi_xfer[IPA_SEND_MAX_DESC];
	int i = 0;
	int j;
	int result;
	u32 mem_flag = GFP_ATOMIC;
	const struct ipa_gsi_ep_config *gsi_ep_cfg;
	bool send_nop = false;
	unsigned int max_desc;

	if (unlikely(!in_atomic))
		mem_flag = GFP_KERNEL;

	gsi_ep_cfg = ipa3_get_gsi_ep_info(sys->ep->client);
	if (unlikely(!gsi_ep_cfg)) {
		IPAERR("failed to get gsi EP config for client=%d\n",
			sys->ep->client);
		return -EFAULT;
	}
	if (unlikely(num_desc > IPA_SEND_MAX_DESC)) {
		IPAERR("max descriptors reached need=%d max=%d\n",
			num_desc, IPA_SEND_MAX_DESC);
		WARN_ON(1);
		return -EPERM;
	}

	max_desc = gsi_ep_cfg->ipa_if_tlv;
	if (gsi_ep_cfg->prefetch_mode == GSI_SMART_PRE_FETCH ||
		gsi_ep_cfg->prefetch_mode == GSI_FREE_PRE_FETCH)
		max_desc -= gsi_ep_cfg->prefetch_threshold;

	if (unlikely(num_desc > max_desc)) {
		IPAERR("Too many chained descriptors need=%d max=%d\n",
			num_desc, max_desc);
		WARN_ON(1);
		return -EPERM;
	}

	/* initialize only the xfers we use */
	memset(gsi_xfer, 0, sizeof(gsi_xfer[0]) * num_desc);

	spin_lock_bh(&sys->spinlock);

	for (i = 0; i < num_desc; i++) {
		tx_pkt = kmem_cache_zalloc(ipa3_ctx->tx_pkt_wrapper_cache,
					   GFP_ATOMIC);
		if (unlikely(!tx_pkt)) {
			IPAERR("failed to alloc tx wrapper\n");
			result = -ENOMEM;
			goto failure;
		}
		INIT_LIST_HEAD(&tx_pkt->link);

		if (i == 0) {
			tx_pkt_first = tx_pkt;
			tx_pkt->cnt = num_desc;
		}

		/* populate tag field */
		if (desc[i].is_tag_status) {
			if (unlikely(ipa_populate_tag_field(&desc[i], tx_pkt,
				&tag_pyld_ret))) {
				IPAERR("Failed to populate tag field\n");
				result = -EFAULT;
				goto failure_dma_map;
			}
		}

		tx_pkt->type = desc[i].type;

		if (desc[i].type != IPA_DATA_DESC_SKB_PAGED) {
			tx_pkt->mem.base = desc[i].pyld;
			tx_pkt->mem.size = desc[i].len;

			if (!desc[i].dma_address_valid) {
				tx_pkt->mem.phys_base =
					dma_map_single(ipa3_ctx->pdev,
					tx_pkt->mem.base,
					tx_pkt->mem.size,
					DMA_TO_DEVICE);
			} else {
				tx_pkt->mem.phys_base =
					desc[i].dma_address;
				tx_pkt->no_unmap_dma = true;
			}
		} else {
			tx_pkt->mem.base = desc[i].frag;
			tx_pkt->mem.size = desc[i].len;

			if (!desc[i].dma_address_valid) {
				tx_pkt->mem.phys_base =
					skb_frag_dma_map(ipa3_ctx->pdev,
					desc[i].frag,
					0, tx_pkt->mem.size,
					DMA_TO_DEVICE);
			} else {
				tx_pkt->mem.phys_base =
					desc[i].dma_address;
				tx_pkt->no_unmap_dma = true;
			}
		}
		if (unlikely(dma_mapping_error(ipa3_ctx->pdev,
			tx_pkt->mem.phys_base))) {
			IPAERR("failed to do dma map.\n");
			result = -EFAULT;
			goto failure_dma_map;
		}

		tx_pkt->sys = sys;
		tx_pkt->callback = desc[i].callback;
		tx_pkt->user1 = desc[i].user1;
		tx_pkt->user2 = desc[i].user2;
		tx_pkt->xmit_done = false;

		list_add_tail(&tx_pkt->link, &sys->head_desc_list);

		gsi_xfer[i].addr = tx_pkt->mem.phys_base;

		/*
		 * Special treatment for immediate commands, where
		 * the structure of the descriptor is different
		 */
		if (desc[i].type == IPA_IMM_CMD_DESC) {
			gsi_xfer[i].len = desc[i].opcode;
			gsi_xfer[i].type =
				GSI_XFER_ELEM_IMME_CMD;
		} else {
			gsi_xfer[i].len = desc[i].len;
			gsi_xfer[i].type =
				GSI_XFER_ELEM_DATA;
		}

		if (i == (num_desc - 1)) {
			if (!sys->use_comm_evt_ring ||
			    (sys->pkt_sent % IPA_EOT_THRESH == 0)) {
				gsi_xfer[i].flags |=
					GSI_XFER_FLAG_EOT;
				gsi_xfer[i].flags |=
					GSI_XFER_FLAG_BEI;
			} else {
				send_nop = true;
			}
			gsi_xfer[i].xfer_user_data =
				tx_pkt_first;
		} else {
			gsi_xfer[i].flags |=
				GSI_XFER_FLAG_CHAIN;
		}
	}

	IPADBG_LOW("ch:%lu queue xfer\n", sys->ep->gsi_chan_hdl);
	result = gsi_queue_xfer(sys->ep->gsi_chan_hdl, num_desc,
			gsi_xfer, true);
	if (unlikely(result != GSI_STATUS_SUCCESS)) {
		IPAERR_RL("GSI xfer failed.\n");
		result = -EFAULT;
		goto failure;
	}

	if (send_nop && !sys->nop_pending)
		sys->nop_pending = true;
	else
		send_nop = false;

	sys->pkt_sent++;
	spin_unlock_bh(&sys->spinlock);

	/* set the timer for sending the NOP descriptor */
	if (send_nop) {

		ktime_t time = ktime_set(0, IPA_TX_SEND_COMPL_NOP_DELAY_NS);

		IPADBG_LOW("scheduling timer for ch %lu\n",
			sys->ep->gsi_chan_hdl);
		hrtimer_start(&sys->db_timer, time, HRTIMER_MODE_REL);
	}

	/* make sure TAG process is sent before clocks are gated */
	ipa3_ctx->tag_process_before_gating = true;

	return 0;

failure_dma_map:
		kmem_cache_free(ipa3_ctx->tx_pkt_wrapper_cache, tx_pkt);

failure:
	ipahal_destroy_imm_cmd(tag_pyld_ret);
	tx_pkt = tx_pkt_first;
	for (j = 0; j < i; j++) {
		next_pkt = list_next_entry(tx_pkt, link);
		list_del(&tx_pkt->link);

		if (!tx_pkt->no_unmap_dma) {
			if (desc[j].type != IPA_DATA_DESC_SKB_PAGED) {
				dma_unmap_single(ipa3_ctx->pdev,
					tx_pkt->mem.phys_base,
					tx_pkt->mem.size, DMA_TO_DEVICE);
			} else {
				dma_unmap_page(ipa3_ctx->pdev,
					tx_pkt->mem.phys_base,
					tx_pkt->mem.size,
					DMA_TO_DEVICE);
			}
		}
		kmem_cache_free(ipa3_ctx->tx_pkt_wrapper_cache, tx_pkt);
		tx_pkt = next_pkt;
	}

	spin_unlock_bh(&sys->spinlock);
	return result;
}

int ipa3_tx_dp(enum ipa_client_type dst, struct sk_buff *skb, struct ipa_tx_meta *meta){
	struct ipa3_desc *desc;
	struct ipa3_desc _desc[3];
	int dst_ep_idx;
	struct ipahal_imm_cmd_pyld *cmd_pyld = NULL;
	struct ipa3_sys_context *sys;
	int src_ep_idx;
	int num_frags, f;
	const struct ipa_gsi_ep_config *gsi_ep;
	int data_idx;
	unsigned int max_desc;

	if (unlikely(!ipa3_ctx)) {
		IPAERR("IPA3 driver was not initialized\n");
		return -EINVAL;
	}

	if (unlikely(skb->len == 0)) {
		IPAERR("packet size is 0\n");
		return -EINVAL;
	}

	/*
	 * USB_CONS: PKT_INIT ep_idx = dst pipe
	 * Q6_CONS: PKT_INIT ep_idx = sender pipe
	 * A5_LAN_WAN_PROD: HW path ep_idx = sender pipe
	 *
	 * LAN TX: all PKT_INIT
	 * WAN TX: PKT_INIT (cmd) + HW (data)
	 *
	 */
	if (IPA_CLIENT_IS_CONS(dst)) {
		src_ep_idx = ipa3_get_ep_mapping(IPA_CLIENT_APPS_LAN_PROD);
		if (unlikely(-1 == src_ep_idx)) {
			IPAERR("Client %u is not mapped\n",
				IPA_CLIENT_APPS_LAN_PROD);
			goto fail_gen;
		}
		dst_ep_idx = ipa3_get_ep_mapping(dst);
	} else {
		src_ep_idx = ipa3_get_ep_mapping(dst);
		if (unlikely(-1 == src_ep_idx)) {
			IPAERR("Client %u is not mapped\n", dst);
			goto fail_gen;
		}
		if (meta && meta->pkt_init_dst_ep_valid)
			dst_ep_idx = meta->pkt_init_dst_ep;
		else
			dst_ep_idx = -1;
	}

	sys = ipa3_ctx->ep[src_ep_idx].sys;

	if (unlikely(!sys || !sys->ep->valid)) {
		IPAERR_RL("pipe %d not valid\n", src_ep_idx);
		goto fail_pipe_not_valid;
	}

	num_frags = skb_shinfo(skb)->nr_frags;
	/*
	 * make sure TLV FIFO supports the needed frags.
	 * 2 descriptors are needed for IP_PACKET_INIT and TAG_STATUS.
	 * 1 descriptor needed for the linear portion of skb.
	 */
	gsi_ep = ipa3_get_gsi_ep_info(ipa3_ctx->ep[src_ep_idx].client);
	if (unlikely(gsi_ep == NULL)) {
		IPAERR("failed to get EP %d GSI info\n", src_ep_idx);
		goto fail_gen;
	}
	max_desc =  gsi_ep->ipa_if_tlv;
	if (gsi_ep->prefetch_mode == GSI_SMART_PRE_FETCH ||
		gsi_ep->prefetch_mode == GSI_FREE_PRE_FETCH)
		max_desc -= gsi_ep->prefetch_threshold;
	if (num_frags + 3 > max_desc) {
		if (unlikely(skb_linearize(skb))) {
			IPAERR("Failed to linear skb with %d frags\n",
				num_frags);
			goto fail_gen;
		}
		num_frags = 0;
	}
	if (num_frags) {
		/* 1 desc for tag to resolve status out-of-order issue;
		 * 1 desc is needed for the linear portion of skb;
		 * 1 desc may be needed for the PACKET_INIT;
		 * 1 desc for each frag
		 */
		desc = kzalloc(sizeof(*desc) * (num_frags + 3), GFP_ATOMIC);
		if (unlikely(!desc)) {
			IPAERR("failed to alloc desc array\n");
			goto fail_gen;
		}
	} else {
		memset(_desc, 0, 3 * sizeof(struct ipa3_desc));
		desc = &_desc[0];
	}

	if (dst_ep_idx != -1) {
		int skb_idx;

		/* SW data path */
		data_idx = 0;
		if (sys->policy == IPA_POLICY_NOINTR_MODE) {
			/*
			 * For non-interrupt mode channel (where there is no
			 * event ring) TAG STATUS are used for completion
			 * notification. IPA will generate a status packet with
			 * tag info as a result of the TAG STATUS command.
			 */
			desc[data_idx].is_tag_status = true;
			data_idx++;
		}
		desc[data_idx].opcode = ipa3_ctx->pkt_init_imm_opcode;
		desc[data_idx].dma_address_valid = true;
		desc[data_idx].dma_address = ipa3_ctx->pkt_init_imm[dst_ep_idx];
		desc[data_idx].type = IPA_IMM_CMD_DESC;
		desc[data_idx].callback = NULL;
		data_idx++;
		desc[data_idx].pyld = skb->data;
		desc[data_idx].len = skb_headlen(skb);
		desc[data_idx].type = IPA_DATA_DESC_SKB;
		desc[data_idx].callback = ipa3_tx_comp_usr_notify_release;
		desc[data_idx].user1 = skb;
		desc[data_idx].user2 = (meta && meta->pkt_init_dst_ep_valid &&
				meta->pkt_init_dst_ep_remote) ?
				src_ep_idx :
				dst_ep_idx;
		if (meta && meta->dma_address_valid) {
			desc[data_idx].dma_address_valid = true;
			desc[data_idx].dma_address = meta->dma_address;
		}

		skb_idx = data_idx;
		data_idx++;

		for (f = 0; f < num_frags; f++) {
			desc[data_idx + f].frag = &skb_shinfo(skb)->frags[f];
			desc[data_idx + f].type = IPA_DATA_DESC_SKB_PAGED;
			desc[data_idx + f].len =
				skb_frag_size(desc[data_idx + f].frag);
		}
		/* don't free skb till frag mappings are released */
		if (num_frags) {
			desc[data_idx + f - 1].callback =
				desc[skb_idx].callback;
			desc[data_idx + f - 1].user1 = desc[skb_idx].user1;
			desc[data_idx + f - 1].user2 = desc[skb_idx].user2;
			desc[skb_idx].callback = NULL;
		}

		if (unlikely(ipa3_send(sys, num_frags + data_idx,
		    desc, true))) {
			IPAERR_RL("fail to send skb %pK num_frags %u SWP\n",
				skb, num_frags);
			goto fail_send;
		}
		IPA_STATS_INC_CNT(ipa3_ctx->stats.tx_sw_pkts);
	} else {
		/* HW data path */
		data_idx = 0;
		if (sys->policy == IPA_POLICY_NOINTR_MODE) {
			/*
			 * For non-interrupt mode channel (where there is no
			 * event ring) TAG STATUS are used for completion
			 * notification. IPA will generate a status packet with
			 * tag info as a result of the TAG STATUS command.
			 */
			desc[data_idx].is_tag_status = true;
			data_idx++;
		}
		desc[data_idx].pyld = skb->data;
		desc[data_idx].len = skb_headlen(skb);
		desc[data_idx].type = IPA_DATA_DESC_SKB;
		desc[data_idx].callback = ipa3_tx_comp_usr_notify_release;
		desc[data_idx].user1 = skb;
		desc[data_idx].user2 = src_ep_idx;

		if (meta && meta->dma_address_valid) {
			desc[data_idx].dma_address_valid = true;
			desc[data_idx].dma_address = meta->dma_address;
		}
		if (num_frags == 0) {
			if (unlikely(ipa3_send(sys, data_idx + 1,
				 desc, true))) {
				IPAERR("fail to send skb %pK HWP\n", skb);
				goto fail_mem;
			}
		} else {
			for (f = 0; f < num_frags; f++) {
				desc[data_idx+f+1].frag =
					&skb_shinfo(skb)->frags[f];
				desc[data_idx+f+1].type =
					IPA_DATA_DESC_SKB_PAGED;
				desc[data_idx+f+1].len =
					skb_frag_size(desc[data_idx+f+1].frag);
			}
			/* don't free skb till frag mappings are released */
			desc[data_idx+f].callback = desc[data_idx].callback;
			desc[data_idx+f].user1 = desc[data_idx].user1;
			desc[data_idx+f].user2 = desc[data_idx].user2;
			desc[data_idx].callback = NULL;

			if (unlikely(ipa3_send(sys, num_frags + data_idx + 1,
			    desc, true))) {
				IPAERR("fail to send skb %pK num_frags %u\n",
					skb, num_frags);
				goto fail_mem;
			}
		}
		IPA_STATS_INC_CNT(ipa3_ctx->stats.tx_hw_pkts);
	}

	if (num_frags) {
		kfree(desc);
		IPA_STATS_INC_CNT(ipa3_ctx->stats.tx_non_linear);
	}
	return 0;

fail_send:
	ipahal_destroy_imm_cmd(cmd_pyld);
fail_mem:
	if (num_frags)
		kfree(desc);
fail_gen:
	return -EFAULT;
fail_pipe_not_valid:
	return -EPIPE;
}

static int ipa3_wwan_xmit(struct sk_buff *skb, struct net_device *dev){
	int ret = 0;
	bool qmap_check;
	struct ipa3_wwan_private *wwan_ptr = netdev_priv(dev);
	unsigned long flags;

	if (unlikely(rmnet_ipa3_ctx->ipa_config_is_apq)) {
		IPAWANERR_RL("IPA embedded data on APQ platform\n");
		dev_kfree_skb_any(skb);
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	if (skb->protocol != htons(ETH_P_MAP)) {
		IPAWANDBG_LOW
		("SW filtering out none QMAP packet received from %s",
		current->comm);
		dev_kfree_skb_any(skb);
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	qmap_check = RMNET_MAP_GET_CD_BIT(skb);
	spin_lock_irqsave(&wwan_ptr->lock, flags);
	/* There can be a race between enabling the wake queue and
	 * suspend in progress. Check if suspend is pending and
	 * return from here itself.
	 */
	if (atomic_read(&rmnet_ipa3_ctx->ap_suspend)) {
		netif_stop_queue(dev);
		spin_unlock_irqrestore(&wwan_ptr->lock, flags);
		return NETDEV_TX_BUSY;
	}
	if (netif_queue_stopped(dev)) {
		if (qmap_check &&
			atomic_read(&wwan_ptr->outstanding_pkts) <
				rmnet_ipa3_ctx->outstanding_high_ctl) {
			IPAWANERR("[%s]Queue stop, send ctrl pkts\n",
							dev->name);
			goto send;
		} else {
			IPAWANERR("[%s]fatal: %s stopped\n", dev->name,
							__func__);
			spin_unlock_irqrestore(&wwan_ptr->lock, flags);
			return NETDEV_TX_BUSY;
		}
	}
	/* checking High WM hit */
	if (atomic_read(&wwan_ptr->outstanding_pkts) >=
		rmnet_ipa3_ctx->outstanding_high) {
		if (!qmap_check) {
			IPAWANDBG_LOW("pending(%d)/(%d)- stop(%d)\n",
				atomic_read(&wwan_ptr->outstanding_pkts),
				rmnet_ipa3_ctx->outstanding_high,
				netif_queue_stopped(dev));
			IPAWANDBG_LOW("qmap_chk(%d)\n", qmap_check);
			netif_stop_queue(dev);
			spin_unlock_irqrestore(&wwan_ptr->lock, flags);
			return NETDEV_TX_BUSY;
		}
	}

send:
	/* IPA_PM checking start */
	/* activate the modem pm for clock scaling */
	ipa_pm_activate(rmnet_ipa3_ctx->q6_pm_hdl);
	ret = ipa_pm_activate(rmnet_ipa3_ctx->pm_hdl);

	if (ret == -EINPROGRESS) {
		netif_stop_queue(dev);
		spin_unlock_irqrestore(&wwan_ptr->lock, flags);
		return NETDEV_TX_BUSY;
	}

	if (unlikely(ret)) {
		IPAWANERR("[%s] fatal: ipa pm activate failed %d\n",
		       dev->name, ret);
		dev_kfree_skb_any(skb);
		dev->stats.tx_dropped++;
		spin_unlock_irqrestore(&wwan_ptr->lock, flags);
		return NETDEV_TX_OK;
	}
	/* IPA_PM checking end */

	/*
	 * increase the outstanding_pkts count first
	 * to avoid suspend happens in parallel
	 * after unlock
	 */
	atomic_inc(&wwan_ptr->outstanding_pkts);
	spin_unlock_irqrestore(&wwan_ptr->lock, flags);

	/*
	 * both data packets and command will be routed to
	 * IPA_CLIENT_Q6_WAN_CONS based on status configuration
	 */
	ret = ipa3_tx_dp(IPA_CLIENT_APPS_WAN_PROD, skb, NULL);
	if (unlikely(ret)) {
		atomic_dec(&wwan_ptr->outstanding_pkts);
		if (ret == -EPIPE) {
			IPAWANERR_RL("[%s] fatal: pipe is not valid\n",
				dev->name);
			dev_kfree_skb_any(skb);
			dev->stats.tx_dropped++;
			return NETDEV_TX_OK;
		}
		ret = NETDEV_TX_BUSY;
		goto out;
	}

	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;
	ret = NETDEV_TX_OK;
out:
	if (atomic_read(&wwan_ptr->outstanding_pkts) == 0) {
		ipa_pm_deferred_deactivate(rmnet_ipa3_ctx->pm_hdl);
		ipa_pm_deferred_deactivate(rmnet_ipa3_ctx->q6_pm_hdl);

	}
	return ret;
}

