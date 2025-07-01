#include<stdio.h>
#include<stdlib.h>
#include <stddef.h>     
#include <unistd.h>     
#include <string.h>     
#include <pthread.h>    
#include <stdint.h>

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
    if (size == 0) return 0;
    if (size > MAX_ALLOC_SIZE) return 0; 
    if (SIZE_MAX - size < sizeof(struct block)) return 0;
    return 1;
}

// check for free blocks
block_t *check_for_free(size_t size) {
    block_t *curr = head;
    while (curr) {
        if(curr->is_free && curr->size >= size) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

// malloc
void *mem_alloc(size_t size) {
    if(!is_safe_allocation(size)) {
        return NULL;
    }

    size_t align_size = (size + 15) & ~15;

    pthread_mutex_lock(&global_malloc_lock);

    // check for free block
    block_t *free_block = check_for_free(align_size);
    if(free_block) {
        free_block->is_free = 0;
        pthread_mutex_unlock(&global_malloc_lock);
        return (void*)(free_block + 1);
    }

    // get new block from OS
    block_t *new_block = sbrk(sizeof(block_t) + align_size);
    if (new_block == (void*)-1) {
        pthread_mutex_unlock(&global_malloc_lock);
        return NULL;
    }

    if(head == NULL) {
        head = new_block;
        tail = new_block;
    }else {
        tail->next = new_block;
        tail = tail->next;
    }

    new_block->is_free = 0;
    new_block->size = align_size;
    new_block->next = NULL;

    pthread_mutex_unlock(&global_malloc_lock);
    return (void*)(new_block + 1);
}

// free
void mem_free() {

}

// realloc
void *re_alloc(size_t size) {

}

// calloc
void *cal_alloc(size_t size) {

}
