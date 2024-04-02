// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include "osmem.h"
#include "helpers.h"

#pragma GCC poison free malloc calloc realloc

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define MIN_BLOCK_SIZE (ALIGN(METADATA_SIZE) + ALIGN(1))

struct block_meta *head;

// return the metadata structure which is located at ptr
struct block_meta *get_current_block(void *ptr)
{
	return (struct block_meta *)((char *)ptr - METADATA_SIZE);
}

// consecutive free blocks are coalesce into a single one.
void coalesce_blocks(struct block_meta *curr)
{
	// iterate through list of blocks and coalesce free blocks
	while (curr->next != NULL && curr->next->status == STATUS_FREE) {
		curr->size += curr->next->size + ALIGN(METADATA_SIZE);
		curr->next = curr->next->next;
	}
}

// split a block in two small ones
void split_block(struct block_meta *block, size_t size)
{
	struct block_meta *new_block = NULL;

	new_block = (struct block_meta *)((char *)block + size + ALIGN(METADATA_SIZE));

	new_block->size = block->size - size - ALIGN(METADATA_SIZE);
	new_block->status = STATUS_FREE;
	new_block->next = block->next;

	block->size = size;
	block->status = STATUS_ALLOC;
	block->next = new_block;
}

// expand current block until meets another allocated block or alloc another one
void *expand_block(void *ptr, struct block_meta *block, size_t size)
{
	// coalesce all blocks to have a larger size
	coalesce_blocks(block);
	if (block->size >= size) {
		if (block->size >= size + MIN_BLOCK_SIZE)
			// if current block is too large split it
			split_block(block, size);
		return ptr;
	} else if (block->next == NULL) {
		// allocate memory to the difference between the new size and the remaining size of the block
		if (sbrk(size - block->size) == (void *) -1)
			return NULL;

		block->size = size;
		return ptr;
	}
	return NULL;
}

void *truncate_block(void *ptr, struct block_meta *block, size_t size)
{
	if (block->size >= size) {
		if (block->size >= size + MIN_BLOCK_SIZE)
			split_block(block, size);
		return ptr;
	}
	return NULL;
}

struct block_meta *find_best_block(struct block_meta **last, size_t size)
{
	struct block_meta *curr = head;
	struct block_meta *best_block = NULL;

	// iterates to the whole list of blocks and find the block size that fits the best with the given size.
	// it also memorize the last block of the list in case it didn't find any block to fit.
	while (curr != NULL) {
		*last = curr;
		if (curr->status == STATUS_FREE) {
			coalesce_blocks(curr);
			if (curr->size >= size) {
				if (best_block == NULL || best_block->size > curr->size)
					best_block = curr;
			}
		}
		curr = curr->next;
	}
	return best_block;
}

struct block_meta *request_space(struct block_meta **last, size_t size)
{
	// blocks larger the MMAP_THRESHOLD are allocated with mmap
	if (size + ALIGN(METADATA_SIZE) >= MMAP_THRESHOLD) {
		struct block_meta *block = NULL;

		block = mmap(NULL, size + ALIGN(METADATA_SIZE), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(block == MAP_FAILED, "mmap");

		block->size = size;
		block->status = STATUS_MAPPED;
		block->next = NULL;
		return block;
	}
	// preallocate memory if it is the first call to allocate memory
	if (head == NULL) {
		head = sbrk(MMAP_THRESHOLD);
		DIE(head == (void *) -1, "sbrk");

		head->size = MMAP_THRESHOLD - ALIGN(METADATA_SIZE);
		head->status = STATUS_FREE;
		head->next = NULL;
	}

	// find a free block which suits the bests with the given size
	struct block_meta *best_block = find_best_block(last, size);

	// split the block if it is possible
	if (best_block != NULL) {
		best_block->status = STATUS_ALLOC;
		if (best_block->size >= size + MIN_BLOCK_SIZE)
			split_block(best_block, size);
		return best_block;
	}
	return NULL;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	size_t align_size = ALIGN(size);

	if (align_size == 0)
		return NULL;

	struct block_meta *last = NULL;
	struct block_meta *block = request_space(&last, align_size);

	// if its find a block return payload
	if (block != NULL)
		return (char *)block + ALIGN(METADATA_SIZE);

	// if we didn't find any free block and the last block is allocated, allocate new block of memory
	// equal to the new size
	if (last->status == STATUS_ALLOC) {
		struct block_meta *new_block = NULL;

		new_block = sbrk(align_size + ALIGN(METADATA_SIZE));
		DIE(new_block == (void *) -1, "sbrk");

		last->next = new_block;

		new_block->size = align_size;
		new_block->status = STATUS_ALLOC;
		new_block->next = NULL;
		return (char *)new_block + ALIGN(METADATA_SIZE);
	}
	// if the last block is free, allocate memory equal to the difference between the new size and the
	// remaining size of the last block
	if (sbrk(align_size - last->size) == (void *) -1)
		return NULL;

	last->size = align_size;
	last->status = STATUS_ALLOC;
	last->next = NULL;
	return (char *)last + ALIGN(METADATA_SIZE);
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr == NULL)
		return;

	struct block_meta *block = get_current_block(ptr);

	// check for double free
	if (block->status == STATUS_FREE)
		return;

	// block is allocated with mmaped then deallocate the memory with munmap
	if (block->status == STATUS_MAPPED)
		DIE(munmap(ptr - ALIGN(METADATA_SIZE), block->size + ALIGN(METADATA_SIZE)) == -1, "munmap");
	else
		block->status = STATUS_FREE;
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	size_t align_size = ALIGN(nmemb * size);

	if (nmemb == 0 || size == 0)
		return NULL;

	// blocks larger then page_size are allocated with mmap
	if (align_size + ALIGN(METADATA_SIZE) >= (unsigned long)sysconf(_SC_PAGESIZE)) {
		struct block_meta *block = NULL;

		block = mmap(NULL, align_size + ALIGN(METADATA_SIZE), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(block == MAP_FAILED, "mmap");

		block->size = align_size;
		block->status = STATUS_MAPPED;
		block->next = NULL;
		// mmap returns zeroed memory so no need to memset the block to 0
		return (char *)block + ALIGN(METADATA_SIZE);
	}
	void *ptr = os_malloc(align_size);

	DIE(ptr == NULL, "os_malloc");

	memset(ptr, 0, align_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	size_t align_size = ALIGN(size);

	if (ptr == NULL) {
		return os_malloc(size);
	} else if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = get_current_block(ptr);

	if (block->status == STATUS_FREE)
		return NULL;

	// blocks larger then MMAP_THRESHOLD are allocated to another place and then the data is copied
	if (align_size + ALIGN(METADATA_SIZE) >= MMAP_THRESHOLD) {
		struct block_meta *new_block = request_space((struct block_meta **)NULL, align_size);
		size_t min_size;

		// get the minimun size between block and size to copy the data
		if (align_size < block->size)
			min_size = align_size;
		else
			min_size = block->size;

		void *new_ptr = (void *)new_block + ALIGN(METADATA_SIZE);

		memcpy(new_ptr, ptr, min_size);
		os_free(ptr);
		return new_ptr;
	} else if (block->status == STATUS_MAPPED) {
		void *new_ptr = os_malloc(align_size);

		DIE(new_ptr == NULL, "os_malloc");

		memcpy(new_ptr, ptr, align_size);
		os_free(ptr);
		return new_ptr;
	}

	// try to truncate current block
	if (truncate_block(ptr, block, align_size) != NULL)
		return ptr;

	// try to expand current block
	if (expand_block(ptr, block, align_size) != NULL)
		return ptr;

	// the block can't be truncated or expanded so it will be reallocated and its content copied
	void *new_ptr = os_malloc(align_size);

	DIE(new_ptr == NULL, "os_malloc");

	memcpy(new_ptr, ptr, block->size);
	os_free(ptr);
	return new_ptr;
}
