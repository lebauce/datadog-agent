int trace_may_open(struct pt_regs *ctx, const struct path *path, int acc_mode, int flag) {
    struct dentry_cache_t data_cache = {};
    // Add process data
    u64 key = fill_process_data(&data_cache.data.process_data);
    // Probe type
    data_cache.data.event = EVENT_MAY_OPEN;

    // Add inode data
    struct dentry *dentry = path->dentry;
    data_cache.data.src_inode = ((struct inode *) dentry->d_inode)->i_ino;
    // Add mode and file data
    data_cache.data.flags = flag;
    data_cache.data.mode = acc_mode;
    // Mount ID
    struct vfsmount *mnt = path->mnt;
    bpf_probe_read(&data_cache.data.src_mount_id, sizeof(int), (void *) mnt + 252);

    // Filter
    if (!filter(&data_cache.data.process_data))
        return 0;

    // Cache event
    data_cache.src_dentry = dentry;
    dentry_cache.update(&key, &data_cache);
    return 0;
}

int trace_ret_may_open(struct pt_regs *ctx) {
    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = dentry_cache.lookup(&key);
    if (!data_cache)
        return 0;
    struct dentry_data_t data = data_cache->data;
    data.retval = PT_REGS_RC(ctx);

    // Resolve dentry
    data.src_pathname_key = bpf_get_prandom_u32();
    resolve_dentry(data_cache->src_dentry, data.src_pathname_key);
    dentry_events.perf_submit(ctx, &data, sizeof(data));
    dentry_cache.delete(&key);
    return 0;
}
