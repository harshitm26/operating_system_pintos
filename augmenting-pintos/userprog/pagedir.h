#ifndef USERPROG_PAGEDIR_H
#define USERPROG_PAGEDIR_H


extern unsigned int init_ram_pages;

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  
#define SWAP_PAGES (4*(init_ram_pages>>4))			//number of pages for swapspace
#define N_FRAMES (2*(init_ram_pages>>4))			//number of pages in framespace
#define SHM_PGS 2				//number of system-wide shared memory pages
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  

#include <stdbool.h>
#include <stdint.h>
#include "threads/synch.h"

uint32_t *pagedir_create (void);
void pagedir_destroy (uint32_t *pd);
bool pagedir_set_page (uint32_t *pd, void *upage, void *kpage, bool rw);
void *pagedir_get_page (uint32_t *pd, const void *upage);
void pagedir_clear_page (uint32_t *pd, void *upage);
bool pagedir_is_dirty (uint32_t *pd, const void *upage);
void pagedir_set_dirty (uint32_t *pd, const void *upage, bool dirty);
bool pagedir_is_accessed (uint32_t *pd, const void *upage);
void pagedir_set_accessed (uint32_t *pd, const void *upage, bool accessed);
void pagedir_activate (uint32_t *pd);

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  
bool pagedir_set_page_framespace (uint32_t *pd, void *upage, void *kpage, bool rw);
bool pagedir_set_page_swapspace (uint32_t *sd, void *upage, void *kpage, bool rw);
uint32_t * lookup_page_in_swapspace (uint32_t *sd, const void *vaddr, bool create);
uint32_t * lookup_page_in_framespace (uint32_t *pd, const void *vaddr, bool create);
unsigned get_free_frame_index();
unsigned get_free_swap_index();
void set_frame_index(unsigned idx, bool value);
void set_swap_index(unsigned idx, bool value);

uint8_t* swapspace;				//pointer to swapspace	
struct bitmap* swapbitmap;		//bitmap for swapspace
uint8_t* framespace;			//pointer to framespace
struct bitmap* framebitmap;		//bitmap for framespace

//int pids[N_FRAMES];

uint8_t* shm_pages[SHM_PGS];	//array for the addresses of different shared memory pages

struct lock shmlock;			//lock for shared memory
struct lock swaplock;			//lock for swapspace
struct lock framelock;			//lock for framespace

bool is_in_framespace(uint8_t* vaddr);
bool is_in_swapspace(uint8_t* vaddr);
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  


#endif /* userprog/pagedir.h */
