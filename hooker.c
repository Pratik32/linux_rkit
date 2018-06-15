#include<linux/module.h>
#include<linux/fs.h>
#include<linux/kernel.h>
#include<linux/unistd.h>
#include<linux/list.h>
#include<linux/mm.h>
#include<linux/init.h>
#include<linux/slab.h>
#include<generated/autoconf.h>
#include<linux/string.h>
#include<linux/kallsyms.h>

MODULE_LICENSE("GPL");

#define MY_MODULE __this_module.name

#define DEBUG(fmt, args...)		printk(fmt, ##args)

#if defined(_CONFIG_X86_)
	#define OP_SIZE 6
#else
	#define OP_SIZE 12
#endif

void hook(void*, void*);
unsigned long disable_write_prot(void);
void enable_write_prot(unsigned long);
unsigned long get_sym_addr(char *);
static int init_list_fs_hooked(void);
int hookme(void);
struct dentry* memfs_lookup_hooked(struct inode*, struct dentry*, unsigned int);
LIST_HEAD(hooks);

struct hook {
	void *addr;
	char orig[OP_SIZE];
	char new[OP_SIZE];
	struct list_head list; 
};

int hookme(void) {
	DEBUG("[%s] Hook me function\n", MY_MODULE);
	return 0;
}

//includes sample hook.
int init_hooker(void) {
	printk("[%s] %s\n", MY_MODULE, __FUNCTION__);
	unsigned long addr = get_sym_addr("memfs_lookup");
	DEBUG("[%s] addr : 0x%lx\n", MY_MODULE, addr);
	if(!addr) {
		DEBUG("[%s] Function not found\n", MY_MODULE);
		return 0;
	}
	void *orig = addr;
	hook(orig, &memfs_lookup_hooked);
	return 0;
}

void exit_hooker(void) {
	hookme();
	printk("[%s] Exiting ...\n", MY_MODULE);
}

void hook(void *orig, void* new) {
	DEBUG("[%s]:%s\n", MY_MODULE, __FUNCTION__);
	unsigned long cr0;
	struct hook *hook_sym;
	unsigned char orig_code[OP_SIZE], new_code[OP_SIZE];
	#if defined(_CONFIG_X86_)
		memcpy(new_code, "\x68\x00\x00\x00\x00\xc3", OP_SIZE);
		DEBUG("X86 : Hooking function 0x%p with 0x%p\n", orig, new);
		*(unsigned long *) &new_code[1] = (unsigned long) new;
    #elif defined(_CONFIG_X86_64_)
		memcpy(new_code, "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0", OP_SIZE);
		DEBUG("X86_64 : Hooking function 0x%p with 0x%p\n", orig, new);
		*(unsigned long *) &new_code[2] = (unsigned long) new;
    #endif
	memcpy(orig_code, orig, OP_SIZE);
	cr0 = disable_write_prot();
	memcpy(orig, new_code, OP_SIZE);
	enable_write_prot(cr0);
	hook_sym = kmalloc(sizeof(struct hook), GFP_KERNEL);
	if(hook_sym == NULL) {
		return;
	}
	memcpy(hook_sym->orig, orig_code, OP_SIZE);
	memcpy(hook_sym->new, new_code, OP_SIZE);
	list_add(&hook_sym->list, &hooks);
}

unsigned long disable_write_prot(void) {
	DEBUG("[%s]Disabling write protection\n", MY_MODULE);
	unsigned long cr0;
	preempt_disable();
	barrier();
	cr0 = read_cr0();
	write_cr0(cr0 & ~X86_CR0_WP);
	DEBUG("[%s]write protection disabled\n", MY_MODULE);
	return cr0;
}

void enable_write_prot(unsigned long cr0) {
	DEBUG("[%s]Enabling write protection\n", MY_MODULE);
	write_cr0(cr0);
	barrier();
	preempt_enable();
	DEBUG("[%s]write protection enabled\n", MY_MODULE);
}

unsigned long get_sym_addr(char *sym) {
	unsigned long addr;
	addr = kallsyms_lookup_name(sym);
	DEBUG("[%s] symbol:%s addr:0x%lx\n", MY_MODULE, sym, addr);
	return addr;
}

int init_list_fs_hooked(void) {
	DEBUG("[%s] init_list_fs hooked.\n", MY_MODULE);
	return 0;
}

//sample hook.
struct dentry* memfs_lookup_hooked(struct inode *dir, struct dentry *dentry,
									unsigned int flags) {
	DEBUG("[%s] memfs_lookup hooked filename = %s\n", MY_MODULE, dentry->d_iname);
	d_add(dentry, NULL);
	return NULL;
}
module_init(init_hooker);
module_exit(exit_hooker);
