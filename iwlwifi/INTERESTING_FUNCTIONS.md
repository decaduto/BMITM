iwl_setup_rx_handlers

iwl_dvm_send_cmd

(from https://elixir.bootlin.com/linux/latest/source/drivers/net/wireless/intel/iwlwifi/dvm/mac80211.c#L220)


```c
static int __iwl_up(struct iwl_priv *priv){
	struct iwl_rxon_context *ctx;
	int ret;

	lockdep_assert_held(&priv->mutex);

	if (test_bit(STATUS_EXIT_PENDING, &priv->status)) {
		IWL_WARN(priv, "Exit pending; will not bring the NIC up\n");
		return -EIO;
	}

	for_each_context(priv, ctx) {
		ret = iwlagn_alloc_bcast_station(priv, ctx);
		if (ret) {
			iwl_dealloc_bcast_stations(priv);
			return ret;
		}
	}

	ret = iwl_trans_start_hw(priv->trans);
	if (ret) {
		IWL_ERR(priv, "Failed to start HW: %d\n", ret);
		goto error;
	}

	ret = iwl_run_init_ucode(priv);
	if (ret) {
		IWL_ERR(priv, "Failed to run INIT ucode: %d\n", ret);
		goto error;
	}

	ret = iwl_trans_start_hw(priv->trans);
	if (ret) {
		IWL_ERR(priv, "Failed to start HW: %d\n", ret);
		goto error;
	}

	ret = iwl_load_ucode_wait_alive(priv, IWL_UCODE_REGULAR);
	if (ret) {
		IWL_ERR(priv, "Failed to start RT ucode: %d\n", ret);
		goto error;
	}

	ret = iwl_alive_start(priv);
	if (ret)
		goto error;
	return 0;

 error:
	set_bit(STATUS_EXIT_PENDING, &priv->status);
	iwl_down(priv);
	clear_bit(STATUS_EXIT_PENDING, &priv->status);

	IWL_ERR(priv, "Unable to initialize device.\n");
	return ret;
}
```

The interesting function are:
	* iwl_trans_start_hw
	* iwl_run_init_ucode
	* iwl_trans_start_hw
	* iwl_load_ucode_wait_alive
	* iwl_alive_start
	

