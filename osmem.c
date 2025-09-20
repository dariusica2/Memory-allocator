// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#include "block_meta.h"

#define ALLOCATION_FAILED		((void *)-1)
#define META_BLOCK_SIZE			sizeof(struct block_meta)
#define MMAP_THRESHOLD			(128 * 1024)

size_t align_size(size_t size);

void *allocate_using_mmap(size_t size);
void *allocate_using_sbrk(size_t size);

void initialize_block(struct block_meta *block, size_t size, int status);
void add_block_in_list(struct block_meta *added_block);

int find_block_in_heap(struct block_meta *searched_block);
struct block_meta *find_last_block(void);
struct block_meta *find_best_block(size_t size);

void coalesce_blocks(struct block_meta *previous_block, struct block_meta *current_block);
void coalesce_all_blocks(void);
void split_block(struct block_meta *old_block, size_t new_size);
void expand_heap(struct block_meta *tail, size_t size);

void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);


static struct block_meta *list_head;

size_t align_size(size_t size)
{
	if (size % 8 != 0)
		size = 8 * (size / 8 + 1);

	return size;
}

void *allocate_using_mmap(size_t size)
{
	void *memory_block;
	size_t total_size;

	total_size = size + META_BLOCK_SIZE;
	memory_block = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (memory_block == ALLOCATION_FAILED)
		return NULL;

	return memory_block;
}

void *allocate_using_sbrk(size_t size)
{
	void *memory_block;
	size_t total_size;

	total_size = size + META_BLOCK_SIZE;
	memory_block = sbrk(total_size);
	if (memory_block == ALLOCATION_FAILED)
		return NULL;

	return memory_block;
}

void initialize_block(struct block_meta *block, size_t size, int status)
{
	block->size = size;
	block->status = status;
	block->next = NULL;
	block->prev = NULL;
}

void add_block_in_list(struct block_meta *added_block)
{
	if (!list_head) {
		list_head = added_block;
	} else {
		struct block_meta *last;

		last = find_last_block();
		added_block->prev = last;
		last->next = added_block;
	}
}

int find_block_in_heap(struct block_meta *searched_block)
{
	struct block_meta *current_block;

	current_block = list_head;
	while (current_block) {
		if (current_block == searched_block)
			return 1;
		current_block = current_block->next;
	}

	return 0;
}

struct block_meta *find_last_block(void)
{
	struct block_meta *current_block;

	current_block = list_head;
	while (current_block->next)
		current_block = current_block->next;

	return current_block;
}

struct block_meta *find_best_block(size_t size)
{
	struct block_meta *current_block;
	struct block_meta *best_block = NULL;

	current_block = list_head;
	while (current_block) {
		if (current_block->status == STATUS_FREE) {
			if (!best_block) {
				if (current_block->size >= size)
					best_block = current_block;
			} else {
				if (best_block->size > current_block->size && current_block->size >= size)
					best_block = current_block;
			}
		}
		current_block = current_block->next;
	}

	return best_block;
}

void coalesce_blocks(struct block_meta *previous_block, struct block_meta *current_block)
{
	previous_block->size += META_BLOCK_SIZE + current_block->size;
	previous_block->next = current_block->next;

	if (current_block->next)
		current_block->next->prev = previous_block;
}

void coalesce_all_blocks(void)
{
	struct block_meta *current_block = list_head;

	while (current_block) {
		if (current_block->status == STATUS_FREE) {
			if (current_block->prev && current_block->prev->status == STATUS_FREE) {
				coalesce_blocks(current_block->prev, current_block);
				current_block = current_block->prev;
			}
		}
		current_block = current_block->next;
	}
}

void split_block(struct block_meta *old_block, size_t new_size)
{
	struct block_meta *added_block;

	added_block = (struct block_meta *)((char *)old_block + META_BLOCK_SIZE + new_size);
	added_block->size = old_block->size - META_BLOCK_SIZE - new_size;
	added_block->status = STATUS_FREE;

	old_block->size = new_size;
	old_block->status = STATUS_ALLOC;

	added_block->prev = old_block;
	added_block->next = old_block->next;

	if (old_block->next)
		old_block->next->prev = added_block;

	old_block->next = added_block;
}

void expand_heap(struct block_meta *tail, size_t size)
{
	sbrk(size - tail->size);
	tail->size = size;
	tail->status = STATUS_ALLOC;
}

void *os_malloc(size_t size)
{
	if (!size)
		return NULL;

	struct block_meta *memory_block;
	struct block_meta *best_block;

	// Aligning size
	size = align_size(size);

	// Initialising the heap
	if (!list_head && size < MMAP_THRESHOLD - META_BLOCK_SIZE) {
		memory_block = (struct block_meta *)allocate_using_sbrk(MMAP_THRESHOLD - META_BLOCK_SIZE);
		if (!memory_block)
			return NULL;

		initialize_block(memory_block, MMAP_THRESHOLD - META_BLOCK_SIZE, STATUS_FREE);
		add_block_in_list(memory_block);
	}

	// Going through the list and coalescing adjacent free blocks
	coalesce_all_blocks();

	// Searching for a block that can hold size bytes
	best_block = find_best_block(size);

	if (best_block) {
		if (best_block->size - size >= META_BLOCK_SIZE + 1)
			split_block(best_block, size);
		else
			best_block->status = STATUS_ALLOC;

		return (void *)((char *)best_block + META_BLOCK_SIZE);
	}

	if (size >= MMAP_THRESHOLD) {
		// Allocate using mmap()
		memory_block = (struct block_meta *)allocate_using_mmap(size);
		if (!memory_block)
			return NULL;

		initialize_block(memory_block, size, STATUS_MAPPED);
	} else {
		// Allocate using sbrk()
		struct block_meta *tail;

		tail = find_last_block();
		if (tail->status == STATUS_FREE) {
			expand_heap(tail, size);
			return (void *)((char *)tail + META_BLOCK_SIZE);
		}

		memory_block = (struct block_meta *)allocate_using_sbrk(size);
		if (!memory_block)
			return NULL;

		initialize_block(memory_block, size, STATUS_ALLOC);
		add_block_in_list(memory_block);
	}

	return (void *)((char *)memory_block + META_BLOCK_SIZE);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *memory_block;

	memory_block = (struct block_meta *)((char *)ptr - META_BLOCK_SIZE);
	if (memory_block->status == STATUS_MAPPED)
		munmap((void *)memory_block, META_BLOCK_SIZE + memory_block->size);
	else
		memory_block->status = STATUS_FREE;
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (!size || !nmemb)
		return NULL;

	struct block_meta *memory_block;

	if (nmemb * size >= 4096 - META_BLOCK_SIZE) {
		size_t array_size;

		array_size = align_size(nmemb * size);
		memory_block = (struct block_meta *)allocate_using_mmap(array_size);
		if (!memory_block)
			return NULL;

		initialize_block(memory_block, array_size, STATUS_MAPPED);
		memset(((char *)memory_block + META_BLOCK_SIZE), 0, nmemb * size);
		return (void *)((char *)memory_block + META_BLOCK_SIZE);
	}

	// Allocation uses malloc() and sbrk() by default
	memory_block = os_malloc(nmemb * size);
	if (!memory_block)
		return NULL;

	memset(memory_block, 0, ((struct block_meta *)((char *)memory_block - META_BLOCK_SIZE))->size);
	return memory_block;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (!size) {
		os_free(ptr);
		return NULL;
	}

	size = align_size(size);

	struct block_meta *memory_block;
	struct block_meta *current_block;
	size_t min_size;

	memory_block = (struct block_meta *)((char *)ptr - META_BLOCK_SIZE);

	min_size = memory_block->size;
	if (size < min_size)
		min_size = size;

	// Going through the list and coalescing adjacent free blocks
	coalesce_all_blocks();

	if (find_block_in_heap(memory_block)) {
		// If status is free
		if (memory_block->status == STATUS_FREE)
			return NULL;

		// If the new size is smaller than the older size
		if (memory_block->size >= size) {
			// If the memory block can be split
			if (memory_block->size - size >= META_BLOCK_SIZE + 1)
				split_block(memory_block, size);

			return (void *)((char *)memory_block + META_BLOCK_SIZE);
		}

		struct block_meta *last;

		// If the given block is the last block in the heap, it needs to be expanded
		last = find_last_block();
		if (memory_block == last) {
			expand_heap(memory_block, size);
			return (void *)((char *)memory_block + META_BLOCK_SIZE);
		}

		// Finding the next free blocks and coalescing them with the current block
		current_block = memory_block;
		while (current_block->next && current_block->next->status == STATUS_FREE) {
			coalesce_blocks(current_block, current_block->next);
			if (current_block->size >= size)
				return (void *)((char *)memory_block + META_BLOCK_SIZE);
		}
	}

	void *new_ptr = os_malloc(size);

	memcpy(new_ptr, ptr, min_size);
	os_free(ptr);
	return new_ptr;
}
