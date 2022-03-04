int iwl_dnt_dev_if_start_monitor(struct iwl_dnt *dnt,
				 struct iwl_trans *trans)
{
	struct iwl_dbg_cfg *cfg = &trans->dbg_cfg;
	int i, ret;

	switch (cfg->dbgm_enable_mode) {
	case DEBUG:
		return iwl_dnt_dev_if_send_dbgm(dnt, trans);
	case SNIFFER:
		ret = 0;
		for (i = 0; i < cfg->ldbg_cmd_nums; i++) {
			ret = iwl_dnt_dev_if_send_ldbg(dnt, trans, i);
			if (ret) {
				IWL_ERR(trans,
					"Failed to send ldbg command\n");
				break;
			}
		}
		return ret;
	default:
		WARN_ONCE(1, "invalid option: %d\n", cfg->dbgm_enable_mode);
		return -EINVAL;
	}
}
