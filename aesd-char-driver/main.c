/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Tom Price");
MODULE_LICENSE("Dual BSD/GPL");

static struct aesd_dev aesd_device;
static struct aesd_buffer_entry newentry;


int aesd_open(struct inode *inode, struct file *filp)
{
	PDEBUG("open");

	/**
	 * TODO: handle open
	 */
	struct aesd_dev *dev; // device information
	dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
	filp->private_data = dev;

	return 0; // success
}


int aesd_release(struct inode *inode, struct file *filp)
{
	PDEBUG("release");
	
	/**
	 * TODO: handle release
	 */
	
	return 0; // success
}


ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	struct aesd_dev *dev;
	uint8_t i, o;
	struct aesd_buffer_entry *entry;
	ssize_t retval = 0;
	PDEBUG("read %zu bytes with offset %lld", count, *f_pos);
	
	/**
	 * TODO: handle read
	 */
	dev = filp->private_data;
	if (mutex_lock_interruptible(&dev->lock)) {
		return -ERESTARTSYS;
	}
	i = dev->cbuf.in_offs;
	o = dev->cbuf.out_offs;
	if (!dev->cbuf.full && i == o) {
		// circular buffer empty: return 0
		goto aesd_read_return;
	}

	entry = &dev->cbuf.entry[o];
	if (*f_pos > entry->size) {
		// EOF: return 0
		goto aesd_read_return;
	}
	if (*f_pos + count >= entry->size) {
		// exhausted data available to be read
		count = entry->size - *f_pos;
		dev->cbuf.out_offs = (o - 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	}

	if (copy_to_user(buf, &entry->buffptr[*f_pos], count)) {
		retval = -EFAULT;
		goto aesd_read_return;
	}
	*f_pos += count;
	retval = count;
	
aesd_read_return:
	mutex_unlock(&dev->lock);
	return retval;
}


ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
	bool newline;
	const char *oldbuf, *newbuf;
	ssize_t retval = -ENOMEM;
	struct aesd_dev *dev;

	newline = (buf[count - 1] == '\n');
	if (newline) {
		PDEBUG("write %zu bytes terminating in newline", count);
	}
	else {
		PDEBUG("write %zu bytes not terminating in newline", count);
	}

	/**
	 * TODO: handle write
	 */
	// make larger buffer for circular buffer entry
	const ssize_t oldsize = newentry.size;
	const ssize_t newsize = oldsize + count;
	newbuf = (char *) kmalloc(newsize, GFP_KERNEL);
	if (newbuf == NULL) {
		// can't allocate memory: return -ENOMEM
		return retval;
	}

	// copy existing data from old buffer to new buffer
	oldbuf = newentry.buffptr;
	if (oldbuf != NULL) {
		(void) memcpy((void *) newbuf, oldbuf, oldsize);
		kfree(oldbuf);
	}

	// copy data to be written into new buffer
	if (copy_from_user((void *) &newbuf[oldsize], buf, count)) {
		retval = -EFAULT;
		return retval;
	}

	if (newline) {
		// write new buffer to circular buffer entry
		newentry.buffptr = newbuf;
		newentry.size = newsize;
		dev = filp->private_data;
		if (mutex_lock_interruptible(&dev->lock)) {
			return -ERESTARTSYS;
		}
		aesd_circular_buffer_add_entry(&dev->cbuf, &newentry);
	}
	retval = count;

	mutex_unlock(&dev->lock);
	return retval;
}


// file operations
struct file_operations aesd_fops = {
	.owner =    THIS_MODULE,
	.read =     aesd_read,
	.write =    aesd_write,
	.open =     aesd_open,
	.release =  aesd_release,
};


static int aesd_setup_cdev(struct aesd_dev *dev)
{
	int err, devno = MKDEV(aesd_major, aesd_minor);
	
	cdev_init(&dev->cdev, &aesd_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &aesd_fops;

	err = cdev_add(&dev->cdev, devno, 1);
	if (err) {
		printk(KERN_ERR "Error %d adding aesd cdev", err);
	}

	return err;
}


int aesd_init_module(void)
{
	dev_t dev = 0;
	int result;
	
	result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
	aesd_major = MAJOR(dev);
	if (result < 0) {
		printk(KERN_WARNING "Can't get major %d\n", aesd_major);
		return result;
	}
	
	memset(&aesd_device, 0, sizeof(struct aesd_dev));
	
	/**
	 * TODO: initialize the AESD specific portion of the device
	 */
	result = aesd_setup_cdev(&aesd_device);
	if (result) {
		goto aesd_init_module_unregister;
	}

	newentry.buffptr = NULL;
	newentry.size = 0;
	
	return result;

aesd_init_module_unregister:
	unregister_chrdev_region(dev, 1);
	return result;
}


void aesd_cleanup_module(void)
{
	dev_t devno = MKDEV(aesd_major, aesd_minor);
	
	cdev_del(&aesd_device.cdev);
	
	/**
	 * TODO: cleanup AESD specific portions here as necessary
	 */
	aesd_circular_buffer_del(&aesd_device.cbuf);
	
	unregister_chrdev_region(devno, 1);
}


module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
