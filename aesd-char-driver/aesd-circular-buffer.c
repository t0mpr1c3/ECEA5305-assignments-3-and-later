/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/string.h>
#else
#include <string.h>
#endif

#undef AESD_DEBUG	/* undef it, just in case */
#define AESD_DEBUG 1	// Remove comment on this line to enable debug

#undef PDEBUG		/* undef it, just in case */
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

#include "aesd-circular-buffer.h"


/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos (struct aesd_circular_buffer *buffer, const size_t char_offset, size_t *entry_offset_byte_rtn)
{
	size_t offset = 0;
	uint8_t index, count;
	struct aesd_buffer_entry *entry;
	const uint8_t i = buffer->in_offs;
	const uint8_t o = buffer->out_offs;
	const bool f = buffer->full;

	// iterate over entries in buffer
	// starting with the entry indexed by buffer->in_offs
	for (
		count = 0,
		index = i,
		entry = &(buffer->entry[index]);

		(count < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) &&
		(f || index != o);

		count += 1,
		index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED,
		entry = &(buffer->entry[index])
	) {
		if (offset + entry->size > char_offset) {
			*entry_offset_byte_rtn = char_offset - offset;
			return entry;
		}
		offset += entry->size;
	}

	return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->out_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->in_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry (struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
	// write entry to buffer at buffer location indexed by output offset
	buffer->entry[buffer->out_offs] = *add_entry;

	if (buffer->full) {
		// buffer full: increment input offset
		buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	}

	// increment output offset
	buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

	// set buffer to full if the input and output offsets are now equal
	buffer->full = (buffer->in_offs == buffer->out_offs);
}

/**
* Returns the total size in bytes of the commands in the circular buffer @param buffer
* starting with the entry 0-indexed by input offset entry
* and including the next @param entry_index entries,
* or -EINVAL if entry_index is greater than the number of entries available to read.
*/
loff_t aesd_circular_buffer_cumulative_size(const struct aesd_circular_buffer *buffer, uint8_t entry_index)
{
	if (entry_index > AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
		// value of entry_index is larger than number of entries in the buffer
		return -EINVAL;
	}

	const uint8_t i = buffer->in_offs;
	const uint8_t o = buffer->out_offs;
	const bool f = buffer->full;

	// iterate over entries in buffer
	// starting with the entry indexed by buffer->in_offs
	loff_t size = 0;
	uint8_t count, index;
	struct aesd_buffer_entry *entry;
	for (
		count = 0,
		index = i,
		entry = (struct aesd_buffer_entry *) &(buffer->entry[index]);

		(count < entry_index);

		count += 1,
		index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED,
		entry = (struct aesd_buffer_entry *) &(buffer->entry[index])
	) {
		if (!f && index == o) {
			// value of entry_index is larger than number of available entries
			return -EINVAL;
		}
		size += entry->size;
	}

	return size;
}

/**
* Returns the total size in bytes of the commands in the circular buffer @param buffer
* starting with the entry 0-indexed by input offset 
* up to and including the entry 0-indexed by the output offset
*/
loff_t aesd_circular_buffer_size(const struct aesd_circular_buffer *buffer)
{
	const uint8_t i = buffer->in_offs;
	const uint8_t o = buffer->out_offs;
	const bool f = buffer->full;
	uint8_t entries = f
		? AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED
		: (o - i + AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	return aesd_circular_buffer_cumulative_size(buffer, entries);
}

/**
* Returns the file offset in bytes for the circular buffer @param buffer
* corresponding to the 0-index @param entry_index
* and the byte offset within that entry @param entry_offset
* or -EINVAL if the parameters are out of range
*/
loff_t aesd_circular_buffer_offset(const struct aesd_circular_buffer *buffer, const uint32_t entry_index, const uint32_t entry_offset)
{
	PDEBUG("in aesd_circular_buffer_offset()");
	uint8_t count, index;
	struct aesd_buffer_entry *entry;
	AESD_CIRCULAR_BUFFER_FOREACH(entry, buffer, index) {
		PDEBUG("%d [%zu]: '%s'", index, entry->size, entry->buffptr);
	}
	const uint8_t i = buffer->in_offs;
	const uint8_t o = buffer->out_offs;
	const bool f = buffer->full;
	PDEBUG("i: %d", i);
	PDEBUG("o: %d", o);
	PDEBUG("f: %d", f);
	
	// iterate over entries in buffer
	// starting with the entry indexed by buffer->in_offs
	loff_t offset = entry_offset;
	for (
		count = 0,
		index = i,
		entry = (struct aesd_buffer_entry *) &(buffer->entry[index]);

		count < entry_index;

		count += 1,
		index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED,
		entry = (struct aesd_buffer_entry *) &(buffer->entry[index])
	) {
		PDEBUG("aesd_circular_buffer_offset: entry->size %zu, count %u, index %u", entry->size, count, index);
		if (!f && index == o) {
			// value of entry_index is larger than number of available entries
			PDEBUG("returning -EINVAL");
			return -EINVAL;
		}
		offset += entry->size;
	}
	PDEBUG("aesd_circular_buffer_offset: entry->size %zu, count %u, index %u", entry->size, count, index);
	if (entry_offset > entry->size) {
		// value of entry_offset is larger than number of bytes in entry
		PDEBUG("returning -EINVAL");
		return -EINVAL;
	}

	PDEBUG("returning %lld", offset);
	return offset;
}

/**
* Returns true if for the circular buffer @param buffer,
* @param entry_index is greater than or equal to AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED, or
* @param byte_index is greater than or equal to the `size` member of the entry 0-indexed by `entry_index`
*/
bool aesd_circular_buffer_out_of_range(const struct aesd_circular_buffer *buffer, const uint8_t entry_index, const uint8_t byte_index)
{
	return 	(entry_index >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) ||
		(byte_index  >= buffer->entry[entry_index].size);
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init (const struct aesd_circular_buffer *buffer)
{
	(void) memset((void *) buffer, 0, sizeof(struct aesd_circular_buffer));
}

/**
* Deletes the circular buffer described by @param buffer
*/
void aesd_circular_buffer_del (const struct aesd_circular_buffer *buffer)
{
	uint8_t index;
	struct aesd_buffer_entry *entry;
	AESD_CIRCULAR_BUFFER_FOREACH(entry, buffer, index) {
#ifdef __KERNEL__
		kfree(entry->buffptr);
#else
		free(entry->buffptr);
#endif
	}
}
