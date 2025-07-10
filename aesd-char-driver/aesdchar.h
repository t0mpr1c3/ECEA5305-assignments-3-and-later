/*
 * aesdchar.h
 *
 *  Created on: Oct 23, 2019
 *      Author: Dan Walkes
 */

#ifndef AESD_CHAR_DRIVER_AESDCHAR_H_
#define AESD_CHAR_DRIVER_AESDCHAR_H_

#include "aesd-circular-buffer.h"

#define AESD_DEBUG 1  //Remove comment on this line to enable debug

#undef PDEBUG             /* undef it, just in case */
#ifdef AESD_DEBUG
#  ifdef __KERNEL__
     /* This one if debugging is on, and kernel space */
#    define PDEBUG(fmt, args...) printk( KERN_DEBUG "aesdchar: " fmt, ## args)
#  else
     /* This one for user space */
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

struct aesd_dev
{
    /**
     * TODO: Add structure(s) and locks needed to complete assignment requirements
     */
    struct cdev cdev;			/* Char device structure */
    struct aesd_circular_buffer cbuf;	/* Circular buffer structure */
    ssize_t size;			/* Number of bytes stored */
    struct mutex lock;
};


extern int aesd_debug(void);

extern int aesd_open(struct inode *inode, struct file *filp);

extern int aesd_release(struct inode *inode, struct file *filp);

extern ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);

extern ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);

extern loff_t aesd_llseek(struct file *filp, loff_t offset, int whence);

extern long aesd_ioctl(struct file *filp, unsigned int magic, unsigned long argp);

static int aesd_setup_cdev(struct aesd_dev *dev);

extern int aesd_init_module(void);

extern void aesd_cleanup_module(void);

#endif /* AESD_CHAR_DRIVER_AESDCHAR_H_ */
