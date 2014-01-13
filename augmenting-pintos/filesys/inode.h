#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "lib/kernel/list.h"
#include "lib/kernel/bitmap.h"
#define SECTOR_NONE ((unsigned int)(-1))

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define N_DIRECT_BLOCKS 12
#define DIRECT_ACCESS N_DIRECT_BLOCKS*BLOCK_SECTOR_SIZE
#define N_INDIRECT_POINTERS (BLOCK_SECTOR_SIZE>>2)
#define INDIRECT_ACCESS N_INDIRECT_POINTERS*BLOCK_SECTOR_SIZE
#define DOUBLE_INDIRECT_ACCESS N_INDIRECT_POINTERS*N_INDIRECT_POINTERS*BLOCK_SECTOR_SIZE
#define MAX_SIZE_INODE_DATA DIRECT_ACCESS+INDIRECT_ACCESS+DOUBLE_INDIRECT_ACCESS
extern unsigned int init_ram_pages;
#define L1_BITS 7
#define L2_BITS 7
#define L3_BITS 9
#define L1_MASK ((1<<(L1_BITS+1))-1)<<(L2_BITS+L3_BITS)
#define L2_MASK ((1<<(L2_BITS+1))-1)<<(L3_BITS)
#define L3_MASK ((1<<(L3_BITS+1))-1)
#define PGSIZE 1<<12
#define BUFF_CACHE_SIZE (4*(init_ram_pages>>5))*PGSIZE
#define N_BUFFERS (BUFF_CACHE_SIZE / BLOCK_SECTOR_SIZE)
#define FREE false
#define OCCUPIED true


struct bitmap;

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    //block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    int type;							// file or directory?    
    block_sector_t direct[N_DIRECT_BLOCKS];
    block_sector_t indirect;
    block_sector_t double_indirect;
    
    uint32_t unused[(BLOCK_SECTOR_SIZE>>2) - 5 - N_DIRECT_BLOCKS];    /* Not used. */
  };

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };
	
struct cached_block
	{
		block_sector_t sector;
		struct inode *inode;
		uint8_t data[BLOCK_SECTOR_SIZE];
		struct list_elem elem;
	};
	
void inode_init (void);
bool inode_create (block_sector_t, off_t);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

void cache_flush(struct inode* inode, block_sector_t sector);
struct cached_block* get_free_cache_buff();
void cache_remove(struct inode* inode, block_sector_t sector);
void cached_write(struct inode* inode, block_sector_t sector, const void *buffer);
void cached_read(struct inode* inode, block_sector_t sector, const void *buffer);
void inode_deallocate_data_blocks(struct inode* inode);


#endif /* filesys/inode.h */

