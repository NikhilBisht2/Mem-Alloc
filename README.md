# Custom Memory Allocator in C

A lightweight, thread-safe memory allocator written in C that mimics the behavior of standard `malloc`, `free`, `calloc`, and `realloc`.

## Features

-  Custom `malloc` (`mem_alloc`)
-  Custom `free` (`mem_free`)
-  Custom `calloc` (`cal_alloc`)
-  Custom `realloc` (`re_alloc`)
-  Thread safety using `pthread_mutex`
-  Block reuse and safe allocation checks
-  Heap shrinking for the last allocated block
-  Memory alignment to 16 bytes
