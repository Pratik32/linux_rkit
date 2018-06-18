#include "common.h"


//hook for memfs_lookup
struct dentry* memfs_lookup_hooked(struct inode *dir, struct dentry *dentry,
									unsigned int flags) {
	struct dentry *ret;
	DEBUG("memfs_lookup hooked filename = %s\n", dentry->d_iname);	
	unsigned long addr = get_sym_addr("memfs_lookup");
	hook_pause((void *)addr);
	struct dentry * (*memfs_lookup_orig)(struct inode *, struct dentry *,
														unsigned int) = addr;
	ret = memfs_lookup_orig(dir, dentry, flags);
	hook_resume((void *)addr);
	return ret;
}

