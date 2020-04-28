int trace_vfs_rename(struct pt_regs *ctx, struct inode *old_dir,
                    struct dentry *old_dentry, struct inode *new_dir,
                    struct dentry *new_dentry, struct inode **delegated_inode,
                    unsigned int flags) {
    struct dentry_cache_t data_cache = {};
    // Add process data
    u64 key = fill_process_data(&data_cache.data.process_data);
    // Probe type
    data_cache.data.event = EVENT_VFS_RENAME;

    // Add old inode data
    data_cache.data.src_inode = ((struct inode *) old_dentry->d_inode)->i_ino;
    // Add old mount ID
    struct super_block *old_spb = old_dentry->d_sb;
    struct list_head *mnt = old_spb->s_mounts.next;
    bpf_probe_read(&data_cache.data.src_mount_id, sizeof(int), (void *) mnt + 172);

    // Filter
    if (!filter(&data_cache.data.process_data))
        return 0;

    // Resolve old dentry
    data_cache.data.src_pathname_key = bpf_get_prandom_u32();
    resolve_dentry(old_dentry, data_cache.data.src_pathname_key);

    // Send to cache
    data_cache.target_dir = new_dir;
    data_cache.target_dentry = new_dentry;
    dentry_cache.update(&key, &data_cache);
    return 0;
}

int trace_ret_vfs_rename(struct pt_regs *ctx) {
    u64 key = bpf_get_current_pid_tgid();
    struct dentry_cache_t *data_cache = dentry_cache.lookup(&key);
    if (!data_cache)
        return 0;
    struct dentry_data_t data = data_cache->data;
    data.retval = PT_REGS_RC(ctx);

    // Add target inode data
    data.target_inode = ((struct inode *) data_cache->target_dentry->d_inode)->i_ino;
    // Add target mount ID
    struct super_block *spb = data_cache->target_dir->i_sb;
    struct list_head *mnt = spb->s_mounts.next;
    bpf_probe_read(&data.target_mount_id, sizeof(int), (void *) mnt + 172);

    // Resolve target dentry
    data.target_pathname_key = bpf_get_prandom_u32();
    resolve_dentry(data_cache->target_dentry, data.target_pathname_key);

    // Send event
    dentry_events.perf_submit(ctx, &data, sizeof(data));
    dentry_cache.delete(&key);
    return 0;
}
