#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_ALLOC_SIZE (1024 * 1024 * 1024)

struct block {
  unsigned is_free;
  size_t size;
  struct block *next;
};
typedef struct block block_t;
block_t *head = NULL;
block_t *tail = NULL;

pthread_mutex_t global_malloc_lock;

// safe for allocation
int is_safe_allocation(size_t size) {
  if (size == 0)
    return 0;
  if (size > MAX_ALLOC_SIZE)
    return 0;
  if (SIZE_MAX - size < sizeof(struct block))
    return 0;
  return 1;
}

// check for free blocks
block_t *check_for_free(size_t size) {
  block_t *curr = head;
  while (curr) {
    if (curr->is_free && curr->size >= size) {
      return curr;
    }
    curr = curr->next;
  }
  return NULL;
}

// malloc
void *mem_alloc(size_t size) {
  if (!is_safe_allocation(size)) {
    return NULL;
  }

  size_t align_size = (size + 15) & ~15;

  pthread_mutex_lock(&global_malloc_lock);

  // check for free block
  block_t *free_block = check_for_free(align_size);
  if (free_block) {
    free_block->is_free = 0;
    pthread_mutex_unlock(&global_malloc_lock);
    return (void *)(free_block + 1);
  }

  // get new block from OS
  block_t *new_block = sbrk(sizeof(block_t) + align_size);
  if (new_block == (void *)-1) {
    pthread_mutex_unlock(&global_malloc_lock);
    return NULL;
  }

  if (head == NULL) {
    head = new_block;
    tail = new_block;
  } else {
    tail->next = new_block;
    tail = tail->next;
  }

  new_block->is_free = 0;
  new_block->size = align_size;
  new_block->next = NULL;

  pthread_mutex_unlock(&global_malloc_lock);
  return (void *)(new_block + 1);
}

void mem_free(void *ptr) {
  if (!ptr)
    return;

  pthread_mutex_lock(&global_malloc_lock);

  block_t *block = (block_t *)ptr - 1;
  void *program_break = sbrk(0);

  char *block_end = (char *)block + sizeof(block_t) + block->size;

  // Check if the block is at the end of the heap
  if (block_end == (char *)program_break) {
    if (head == tail) {
      head = tail = NULL;
    } else {
      block_t *curr = head;
      while (curr && curr->next != tail) {
        curr = curr->next;
      }
      if (curr) {
        curr->next = NULL;
        tail = curr;
      }
    }

    sbrk(0 - (sizeof(block_t) + block->size));
  } else {
    block->is_free = 1;
  }

  pthread_mutex_unlock(&global_malloc_lock);
}

// realloc
void *re_alloc(void *ptr, size_t size) {
  if (!ptr)
    return mem_alloc(size);
  if (size == 0) {
    mem_free(ptr);
    return NULL;
  }

  block_t *old_block = (block_t *)ptr - 1;

  // reuse the old block
  if (old_block->size >= size) {
    return ptr;
  }

  void *new_ptr = mem_alloc(size);
  if (!new_ptr)
    return NULL;

  memcpy(new_ptr, ptr, old_block->size);
  mem_free(ptr);

  return new_ptr;
}

// calloc
void *cal_alloc(size_t num, size_t size) {
  if (!num || !size)
    return NULL;

  size_t total = num * size;

  if (num != 0 && total / num != size)
    return NULL;

  void *ptr = mem_alloc(total);
  if (!ptr)
    return NULL;

  memset(ptr, 0, total);
  return ptr;
}

int main() {

  // testing
  void *a = mem_alloc(100);
  void *b = cal_alloc(10, 10);
  void *c = re_alloc(a, 200);
  mem_free(b);
  mem_free(c);

  void *d = mem_alloc(100);
  mem_free(d);

  return 0;
}
