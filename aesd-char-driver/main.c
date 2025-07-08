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

MODULE_AUTHOR("Tom Price");
MODULE_LICENSE("Dual BSD/GPL");

static int aesd_major =   0; // use dynamic major
static int aesd_minor =   0;

DEFINE_MUTEX(aesd_lock);
static struct aesd_dev aesd_device;
static struct aesd_buffer_entry aesd_entry;


int aesd_debug(void) {
	uint8_t index;
	struct aesd_buffer_entry *entry;

	const struct mutex *lock = &(aesd_device.lock);
	if (mutex_lock_interruptible((struct mutex *) lock)) {
		return -ERESTARTSYS;
	}

	AESD_CIRCULAR_BUFFER_FOREACH(entry, &(aesd_device.cbuf), index) {
		PDEBUG("%d [%zu]: '%s'", index, entry->size, entry->buffptr);
	}
	PDEBUG("i: %d", aesd_device.cbuf.in_offs);
	PDEBUG("o: %d", aesd_device.cbuf.out_offs);
	PDEBUG("f: %d", aesd_device.cbuf.full);

	PDEBUG("E: [%zu]: '%s'", aesd_entry.size, aesd_entry.buffptr);

	mutex_unlock((struct mutex *) lock);
	return 0;
}


int aesd_open(struct inode *inode, struct file *filp)
{
	PDEBUG("in aesd_open()");
	PDEBUG("open inode %lu", inode->i_ino);

	/**
	 * TODO: handle open
	 */
	struct aesd_dev *dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
	filp->private_data = (void *) dev;

	return 0; // success
}


int aesd_release(struct inode *inode, struct file *filp)
{
	PDEBUG("in aesd_release()");
	PDEBUG("release inode %lu", inode->i_ino);
	
	/**
	 * TODO: handle release
	 */
	
	return 0; // success
}


ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	PDEBUG("in aesd_read()");
	PDEBUG("count %zu, f_pos %llu", count, *f_pos);
	struct aesd_dev *dev;
	uint8_t i, o;
	bool f;
	loff_t p = *f_pos;
	struct aesd_buffer_entry *entry;
	size_t entry_size;
	ssize_t read_size, retval = 0;
	
	/**
	 * TODO: handle read
	 */
	dev = (struct aesd_dev *) filp->private_data;
	i = dev->cbuf.in_offs;
	o = dev->cbuf.out_offs;
	f = dev->cbuf.full;

	// obtain mutex
	const struct mutex *lock = &(dev->lock);
	if (mutex_lock_interruptible((struct mutex *) lock)) {
		return -ERESTARTSYS;
	}
	PDEBUG("obtained mutex");

	while (count > 0) {

		// check if we have read everything in the circular buffer
		if (!f && i == o) {
			PDEBUG("nothing left to read");
			break;
		}
	
		// get buffer entry
		entry = &(dev->cbuf.entry[o]);
		entry_size = entry->size;
	
		// get read size
		read_size = 0;
		if (p + count >= entry_size) {
			read_size = entry_size - p;
		}

		if (read_size > 0) {
			// copy data from kernel space
			if (copy_to_user((void __user *) &(buf[retval]), (const void *) &(entry->buffptr[p]), read_size)) {
				retval = -EFAULT;
				goto aesd_read_return;
			}
			count -= read_size;
			p += read_size;
			retval += read_size;
			PDEBUG("read %zu bytes from entry %d", read_size, o);
		}
	
		if (p >= entry_size) {
			// move the buffer read pointer up
			o = (o + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
			f = false;
			p -= entry_size;
		}

	}

	// advance offset
	*f_pos += retval;
	PDEBUG("%zu bytes read", retval);

aesd_read_return:
	// release mutex
	mutex_unlock((struct mutex *) lock);
	PDEBUG("released mutex");
	//(void) aesd_debug();

	return retval;
}


ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
	PDEBUG("in aesd_write()");
	struct aesd_dev *dev;
	ssize_t retval = -ENOMEM;

	/**
	 * TODO: handle write
	 */
	dev = (struct aesd_dev *) filp->private_data;

	// obtain mutex
	const struct mutex *lock = &(dev->lock);
	PDEBUG("`lock` points to (struct mutex *)%p", lock);
	if (mutex_lock_interruptible((struct mutex *) lock)) {
		return -ERESTARTSYS;
	}
	PDEBUG("obtained mutex");

	const uint8_t i = dev->cbuf.in_offs;
	const bool newline = (buf[count - 1] == '\n');
	PDEBUG("writing %zu bytes %sterminating in newline to entry %d", count, newline ? "" : "not ", i);

	// make larger buffer for circular buffer entry
	const size_t oldsize = aesd_entry.size;
	const size_t newsize = oldsize + count;
	char *newbuf = (char *) kmalloc(newsize + (newline ? 1 : 0), GFP_KERNEL);
	if (newbuf == NULL) {
		// can't allocate memory: return -ENOMEM
		goto aesd_write_return;
	}

	// copy existing data from old buffer to new buffer
	const char *oldbuf = aesd_entry.buffptr;
	if (oldbuf != NULL) {
		(void) memcpy((void *) newbuf, (const void *) oldbuf, oldsize);
		kfree(oldbuf);
	}

	// copy data to be written into new buffer
	if (copy_from_user((void *) &(newbuf[oldsize]), (const void __user *) buf, count)) {
		retval = -EFAULT;
		goto aesd_write_return;
	}

	if (newline) {
		// terminate string with 0
		newbuf[newsize] = (char) 0;

		// write new buffer to circular buffer entry
		struct aesd_buffer_entry *newentry = kmalloc(sizeof(struct aesd_buffer_entry), GFP_KERNEL);
		if (newentry == NULL) {
			// can't allocate memory: return -ENOMEM
			goto aesd_write_return;
		}
		newentry->buffptr = (const char *) newbuf;
		newentry->size = newsize;
		aesd_circular_buffer_add_entry(&(dev->cbuf), newentry);

		// clear aesd_entry
		aesd_entry.buffptr = NULL;
		aesd_entry.size = 0;
	}
	else {
		// store concatenated string
		aesd_entry.buffptr = newbuf;
		aesd_entry.size = newsize;
	}
	retval = count;

aesd_write_return:
	// release mutex
	mutex_unlock((struct mutex *) lock);
	PDEBUG("released mutex");
	//(void) aesd_debug();

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
	
	cdev_init(&(dev->cdev), &aesd_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &aesd_fops;

	err = cdev_add(&(dev->cdev), devno, 1);
	if (err) {
		printk(KERN_ERR "Error %d adding aesd cdev", err);
	}

	return err;
}


int aesd_init_module(void)
{
	PDEBUG("in aesd_init_module()");
	dev_t dev = 0;
	int result;
	
	result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
	aesd_major = MAJOR(dev);
	if (result < 0) {
		printk(KERN_WARNING "Can't get major %d\n", aesd_major);
		return result;
	}
	PDEBUG("initialized /dev/aesdchar to major %d, minor %d", aesd_major, aesd_minor);
	
	/**
	 * TODO: initialize the AESD specific portion of the device
	 */
	result = aesd_setup_cdev(&aesd_device);
	if (result) {
		goto aesd_init_module_unregister;
	}
	aesd_circular_buffer_init(&(aesd_device.cbuf));
	aesd_device.size = 0;
	aesd_device.lock = aesd_lock;

	aesd_entry.buffptr = NULL;
	aesd_entry.size = 0;
	
	return result;

aesd_init_module_unregister:
	unregister_chrdev_region(dev, 1);
	return result;
}


void aesd_cleanup_module(void)
{
	PDEBUG("in aesd_cleanup_module()");
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
