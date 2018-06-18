#include<linux/unistd.h>
#include<linux/init.h>
#include<generated/autoconf.h>
#include<linux/string.h>
#include<linux/kallsyms.h>

#include "common.h"

MODULE_LICENSE("GPL");

#if defined(_CONFIG_X86_)
	#define OP_SIZE 6
#else
	#define OP_SIZE 12
#endif

#define X86_64_OPCODE		"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
#define X86_OPCODE			"\x68\x00\x00\x00\x00\xc3"

void hook(void*, void*);
void hook_pause(void*);
void hook_resume(void*);
unsigned long disable_write_prot(void);
void enable_write_prot(unsigned long);
unsigned long get_sym_addr(char *);
struct hook* get_hooked_sym(void *);
static int init_list_fs_hooked(void);
void destroy_hooker(void);

LIST_HEAD(hooks);

struct hook {
	void *addr;
	char orig[OP_SIZE];
	char new[OP_SIZE];
	struct list_head list; 
};

//includes sample hook.
int init_hooker(void) {
	DEBUG("%s\n", __FUNCTION__);
	unsigned long addr = get_sym_addr("memfs_lookup");
	if(!addr) {
		DEBUG("Function not found\n");
		return 0;
	}
	void *orig = addr;
	hook(orig, &memfs_lookup_hooked);
	return 0;
}

void exit_hooker(void) {
	DEBUG("Exiting ...\n");
	destroy_hooker();
}

void destroy_hooker(void) {
	struct hook *hook;
	list_for_each_entry(hook, &hooks, list) {
		kfree(hook);
	}
}

void hook(void *orig, void* new) {
	DEBUG("%s\n", __FUNCTION__);
	unsigned long cr0;
	struct hook *hook_sym;
	unsigned char orig_code[OP_SIZE], new_code[OP_SIZE];
	/*#if defined(CONFIG_X86)
		memcpy(new_code, X86_OPCODE, OP_SIZE);
		DEBUG("X86 : Hooking function 0x%p with 0x%p\n", orig, new);
		*(unsigned long *) &new_code[1] = (unsigned long) new;
    #elif defined(CONFIG_X86_64)*/
		memcpy(new_code, X86_64_OPCODE, OP_SIZE);
		DEBUG("X86_64 : Hooking function 0x%p with 0x%p\n", orig, new);
		*(unsigned long *) &new_code[2] = (unsigned long) new;
   // #endif
	memcpy(orig_code, orig, OP_SIZE);
	cr0 = disable_write_prot();
	memcpy(orig, new_code, OP_SIZE);
	enable_write_prot(cr0);
	hook_sym = kmalloc(sizeof(struct hook), GFP_KERNEL);
	if(hook_sym == NULL) {
		return;
	}
	hook_sym->addr = orig;
	memcpy(hook_sym->orig, orig_code, OP_SIZE);
	memcpy(hook_sym->new, new_code, OP_SIZE);
	list_add(&hook_sym->list, &hooks);
}

void hook_pause(void *func) {
	DEBUG("pausing hook for 0x%p\n", func);
	struct hook *hook;
	hook = get_hooked_sym(func);
	if(hook == NULL) {
		DEBUG("Hook Pause failed\n");
	}
	unsigned long cr0;
	cr0 = disable_write_prot();
	memcpy(func, (void*)hook->orig, OP_SIZE);
	enable_write_prot(cr0);
	DEBUG("function hooking pause for 0x%p\n", func);
}

void hook_resume(void *func) {
	struct hook *hook;
	hook = get_hooked_sym(func);
	if(hook == NULL) {
		DEBUG("Hook Resume failed\n");
		return;
	}
	unsigned long cr0;
	cr0 = disable_write_prot();
	memcpy(func, (void*)hook->new, OP_SIZE);
	enable_write_prot(cr0);
}

struct hook* get_hooked_sym(void *func) {
	struct hook *hook;
	list_for_each_entry(hook, &hooks, list) {
		DEBUG("entry : 0x%p\n", hook->addr);
		if(hook->addr == func) {
			DEBUG("Entry found:0x%p\n", hook->addr);
			break;
		}
	}
	if(!hook || hook->addr != func) {
		DEBUG("Entry not find\n");
		return NULL;
	}
	return hook;
}

unsigned long disable_write_prot(void) {
	DEBUG("Disabling write protection\n");
	unsigned long cr0;
	preempt_disable();
	barrier();
	cr0 = read_cr0();
	write_cr0(cr0 & ~X86_CR0_WP);
	DEBUG("write protection disabled\n");
	return cr0;
}

void enable_write_prot(unsigned long cr0) {
	DEBUG("Enabling write protection\n");
	write_cr0(cr0);
	barrier();
	preempt_enable();
	DEBUG("write protection enabled\n");
}

unsigned long get_sym_addr(char *sym) {
	unsigned long addr;
	addr = kallsyms_lookup_name(sym);
	DEBUG("symbol:%s addr:0x%lx\n", sym, addr);
	return addr;
}

module_init(init_hooker);
module_exit(exit_hooker);
