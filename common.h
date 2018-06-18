#include<linux/fs.h>
#include<linux/kernel.h>
#include<linux/slab.h>
#include<linux/list.h>
#include<linux/mm.h>
#include<linux/module.h>


struct dentry* memfs_lookup_hooked(struct inode*, struct dentry*, unsigned int);
unsigned long get_sym_addr(char *);
void hook_pause(void*);
void hook_resume(void*);

#define MY_MODULE 			__this_module.name
#define CONCAT(fmt)			"[%s]:"fmt
#define DEBUG(fmt, args...)	printk(CONCAT(fmt), MY_MODULE, ##args)

