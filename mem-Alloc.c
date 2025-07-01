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
void *check_for_free(size_t size) {
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

    pthread_mutex_lock(&global_malloc_lock);

    // check for free block
    if(check_for_free(size)) {
        block_t *block = check_for_free(size);
    }




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
