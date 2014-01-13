#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#define INODE_DEBUG 0
/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

size_t sectors_to_allocate(off_t size){ //no of data blocks to allocate
	int res=0;
	if(size<=DIRECT_ACCESS) return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
	else if(size <= DIRECT_ACCESS + INDIRECT_ACCESS){
		res += N_DIRECT_BLOCKS;
		res += 1;
		size -= DIRECT_ACCESS;
		res += size/BLOCK_SECTOR_SIZE;
		return res; 
	}
	else if(size <= DIRECT_ACCESS + INDIRECT_ACCESS + DOUBLE_INDIRECT_ACCESS){
		res += N_DIRECT_BLOCKS;
		size -= DIRECT_ACCESS;
		res += 1; //indirect block
		res += N_INDIRECT_POINTERS;
		size -= INDIRECT_ACCESS;
		res += 1; //double indirect block
		int i,j;
		for(i=0; i<N_INDIRECT_POINTERS, size >0; i++){ //inside double indirect block
			res +=1;
			for(j=0; j<N_INDIRECT_POINTERS, size >0; j++){
				res += 1;
				size -= BLOCK_SECTOR_SIZE;
			}
		}
		return res;
	}
	else return -1;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (struct inode *inode, off_t pos) 
{
  if(INODE_DEBUG) printf("byte_to_sector(%x, %d)\n", inode, pos);
  ASSERT (inode != NULL);
  ASSERT (inode->data.length < MAX_SIZE_INODE_DATA);
  ASSERT (pos < MAX_SIZE_INODE_DATA);
  ASSERT (pos - inode->data.length < BLOCK_SECTOR_SIZE);
  if(pos < DIRECT_ACCESS){
	  int idx = pos/BLOCK_SECTOR_SIZE;
	  block_sector_t b = inode->data.direct[idx];
	  if(b!=0) return b;
	  //printf("byte_to_sector(): pos: %d size: %d\n", pos, inode->data.length);
	  ASSERT(pos-inode->data.length >0);
	  free_map_allocate(1, &b);
	  inode->data.direct[idx]= b;
	  inode->data.length+= pos - inode->data.length;
	  return b;
  }		  
  else if(pos < DIRECT_ACCESS+INDIRECT_ACCESS){
	  uint32_t* indirect_block = (uint32_t*)calloc(BLOCK_SECTOR_SIZE, 1);
	  if(inode->data.indirect ==0){
		ASSERT( pos - inode->data.length >0);
		block_sector_t indir;
		free_map_allocate(1, &indir);
		inode->data.indirect =indir;
	  }
	  cached_read(inode, inode->data.indirect, indirect_block);
	  int idx = (pos-DIRECT_ACCESS)/BLOCK_SECTOR_SIZE;
	  block_sector_t b =  indirect_block[idx];
		if(b==0){
		  ASSERT( pos - inode->data.length >0);
		  free_map_allocate(1, &b);
		  indirect_block[idx]=b;
		  block_write(fs_device, inode->data.indirect, indirect_block);
		  //cache_flush(inode, inode->data.indirect);
		  inode->data.length += pos - inode->data.length;
	  }
	  free(indirect_block);
	  return b;
  }
  else{
	  uint32_t* level_one_block = (uint32_t*)malloc(BLOCK_SECTOR_SIZE);
	  if(inode->data.double_indirect==0){
		  ASSERT(pos-inode->data.length > 0);
		  block_sector_t b;
		  free_map_allocate(1, &b);
		  inode->data.double_indirect = b;
	  }
	  block_read(inode, inode->data.double_indirect, level_one_block);
	  off_t eff = pos-DIRECT_ACCESS-INDIRECT_ACCESS;
	  int idx1 = eff>>(L2_BITS+L3_BITS);
	  block_sector_t level_two_block_no = level_one_block[idx1];
	  if(level_two_block_no ==0){
		  ASSERT(pos- inode->data.length>0);
		  free_map_allocate(1, &level_two_block_no);
		  level_one_block[idx1]=level_two_block_no;
		  block_write(fs_device, inode->data.double_indirect, level_one_block);
		  //cache_flush(inode, inode->data.double_indirect);
	  }
	  uint32_t* level_two_block = (uint32_t*)malloc(BLOCK_SECTOR_SIZE);
	  block_read(inode, level_two_block_no, level_two_block);
	  int idx2 = (eff&L2_MASK)>>L3_BITS;
	  block_sector_t level_three_block_no = level_two_block[idx2];
	  if(level_three_block_no == 0){
		  ASSERT(pos-inode->data.length >0);
		  free_map_allocate(1, &level_three_block_no);
		  level_two_block[idx2]=level_three_block_no;
		  block_write(fs_device, level_two_block_no, level_two_block);
		  //cache_flush(inode, level_two_block_no);
		  inode->data.length += pos - inode->data.length;
	  }
	  free(level_one_block);
	  free(level_two_block);
	  return level_three_block_no;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list buffcachelist;
static struct list open_inodes;
struct bitmap* cache_bitmap;
struct cached_block* buffcache;
/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&buffcachelist);
  list_init (&open_inodes);
  buffcache = (uint8_t*)malloc(BUFF_CACHE_SIZE);
  cache_bitmap = bitmap_create(N_BUFFERS);
  if(INODE_DEBUG) printf("inode_init(): cache_bitmap NULL! N_BUFFERS: %d init_ram_pages %d \n", N_BUFFERS, 4*(init_ram_pages>>4));
  bitmap_set_all(cache_bitmap, FREE);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0 && length<MAX_SIZE_INODE_DATA);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t allocated_sectors = sectors_to_allocate (length);
      size_t data_sectors = bytes_to_sectors(length);
      ASSERT(allocated_sectors >= data_sectors);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      block_sector_t start_sector=0;
      //~ printf("HERERERERERERERERERERERERERERERER1\n");
      if (free_map_allocate (allocated_sectors, &start_sector)) 
        {
		  
          if (data_sectors > 0) 
            {
			  ASSERT(start_sector>0);
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              uint32_t* buff = (uint32_t*)malloc(BLOCK_SECTOR_SIZE);
              int current_sector = start_sector;
              for (i = 0; i < N_DIRECT_BLOCKS && data_sectors>0; i++, data_sectors--){
				//~ printf("HERERERERERERERERERERERERERERERER2 current_sector %d\n", current_sector);
                disk_inode->direct[i]=current_sector;
                //~ cached_write (NULL, current_sector, zeros);
                //~ cache_flush(NULL, current_sector);
                block_write (fs_device, current_sector, zeros);
                
                current_sector++;
              }
              if(data_sectors>0){
				  disk_inode->indirect=current_sector;
				  memset(buff, 0, BLOCK_SECTOR_SIZE);
				  int indir=0;
				  for(i=0; i<N_INDIRECT_POINTERS && data_sectors>0; i++, data_sectors--){
					  //~ printf("HERERERERERERERERERERERERERERERER3\n");
					  buff[i]= current_sector+i+1;
					  indir++;
				  }
				  //~ cached_write(NULL, current_sector, buff);//writing the block containing indirect pointers
				  //~ cache_flush(NULL, current_sector);
				  block_write(fs_device, current_sector, buff);
				  current_sector++;
				  for(i=0; i<indir; i++){
					  //~ printf("HERERERERERERERERERERERERERERERER4\n");
					  block_write(fs_device, current_sector, zeros);
					  //block_flush(NULL, current_sector);
					  current_sector++;
				  }
			  }
			  if(data_sectors>0){
				  disk_inode->double_indirect = current_sector;
				  memset(buff, 0, BLOCK_SECTOR_SIZE);
				  for(i=0; i<DIV_ROUND_UP(data_sectors, N_INDIRECT_POINTERS); i++){
					  //~ printf("HERERERERERERERERERERERERERERERER5\n");
					  buff[i] = current_sector+1+i*(N_INDIRECT_POINTERS+1);
				  }
				  //~ cached_write(NULL, current_sector, buff);
				  //~ cache_flush(NULL, current_sector);
				  block_write(fs_device, current_sector, buff);
				  current_sector++;
				  for(i=0; i<DIV_ROUND_UP(data_sectors, N_INDIRECT_POINTERS); i++){
					  //~ printf("HERERERERERERERERERERERERERERERER6\n");
					  memset(buff, 0, BLOCK_SECTOR_SIZE);
					  int j, indir=0;
					  for(j=0; j<N_INDIRECT_POINTERS, data_sectors>0; j++, data_sectors--){
						  //~ printf("HERERERERERERERERERERERERERERERER7\n");
						buff[j] = current_sector+j+1;
						indir++;
					  }  
					  //~ cached_write(NULL, current_sector, buff);
					  //~ cache_flush(NULL, current_sector);
					  block_write(fs_device, current_sector, buff);
					  current_sector++;
					  for(j=0; j<indir; j++){
						  //~ cached_write(NULL, current_sector, zeros);
						  //~ cache_flush(NULL, current_sector);
						  block_write(fs_device, current_sector, zeros);
						  current_sector++;
					  }
				  }
				  ASSERT(current_sector-start_sector== allocated_sectors);
			  } 
            }
          //~ printf("inode_create: disk_inode->direct[0]=%d\n", disk_inode->direct[0]);
          if(sector!=0){
			//~ cached_write (fs_device, sector, disk_inode);
			//~ cache_flush(NULL, sector);
			block_write (fs_device, sector, disk_inode);
		  }else{
			block_write(fs_device, sector, disk_inode);
		  }
          //~ block_read(fs_device, sector, disk_inode);
          //~ ASSERT(disk_inode->direct[0]!=0);
          success = true; 
        } 
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  printf("inode_open(%u)\n", sector);
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
	  printf("in inode_open()\n");
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
		  printf("inode_open(): inode found in open_inodes list\n");
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL){
	printf("Could not create new inode\n");
    return NULL;
  }

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  //inode->type=...
  cached_read (inode, inode->sector, &inode->data); //Assignment 4
  printf("inode_open(): Successfully created new inode\n");
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) //inode is to be deleted
        {
		  cache_remove(inode,SECTOR_NONE);
		  inode_deallocate_data_blocks(inode);
          free_map_release (inode->sector, 1);
          //free_map_release (inode->data.start, bytes_to_sectors (inode->data.length)); 
          free(inode);
          return;
        }
	  cache_flush(inode,SECTOR_NONE);
	  cache_remove(inode,SECTOR_NONE);
      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cached_read (inode, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cached_read (inode, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      //off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      //int min_left = inode_left < sector_left ? inode_left : sector_left;
      int min_left = sector_left;
      

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if(offset > inode_length(inode)) inode->data.length += chunk_size;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cached_write (NULL, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            cached_read (inode, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cached_write (NULL, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}


struct cached_block* get_free_cache_buff(){
	if(INODE_DEBUG) printf("get_free_cache_buff()\n");
	int idx = bitmap_scan_and_flip(cache_bitmap, 0, 1, FREE);
	
	if(idx != BITMAP_ERROR){
		
		struct cached_block* newblock = buffcache + idx;
		if(INODE_DEBUG) printf("get_free_cache_buff(): idx %d buffcache %x newblock %x buffcache+BUFF_CACHE_SIZE %x\n", idx, buffcache, newblock, buffcache+N_BUFFERS);
		
		memset(newblock, 0, sizeof(struct cached_block));
		
		list_push_front(&buffcachelist, &newblock->elem);
		
		
		return newblock;
	}
	else{
		struct cached_block* last_block = list_entry(list_back(&buffcache), struct cached_block, elem);
		cache_flush(NULL, last_block->sector);
		list_remove(&last_block->elem);
		traverse_buffcachelist();
		list_push_front(&buffcachelist, &last_block->elem);
		memset(last_block->data, 0, BLOCK_SECTOR_SIZE);
		last_block->inode=NULL;
		last_block->sector=0;
		if(INODE_DEBUG) printf("get_free_cache_buff(): idx %d buffcache %x lastblock %x buffcache+BUFF_CACHE_SIZE %x\n", idx, buffcache, last_block, buffcache+N_BUFFERS);
		return last_block;
	}
}

void inode_deallocate_data_blocks(struct inode* inode){
	struct inode_disk disk_inode = inode->data;
	int i, size = disk_inode.length;
	if(size<=DIRECT_ACCESS){
		for(i=0; i<DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); i++){
			free_map_release(disk_inode.direct[i], 1);
		}
		return;
	}
	if(size<= DIRECT_ACCESS+INDIRECT_ACCESS){
		for(i=0; i<N_DIRECT_BLOCKS; i++){
			free_map_release(disk_inode.direct[i], 1);
		}
		size-=DIRECT_ACCESS;
		uint32_t* indirect_block = (uint32_t*)malloc(BLOCK_SECTOR_SIZE);
		cached_read(inode, disk_inode.indirect,indirect_block);
		for(i=0; i<DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); i++){
			free_map_release(indirect_block[i], 1);
		}
		free_map_release(disk_inode.indirect, 1);
		free(indirect_block);
		return;
	}
	if(size<=DIRECT_ACCESS+INDIRECT_ACCESS+DOUBLE_INDIRECT_ACCESS){
		uint32_t* buff = (uint32_t*)malloc(BLOCK_SECTOR_SIZE);
		for(i=0; i<N_DIRECT_BLOCKS; i++){
			free_map_release(disk_inode.direct[i], 1);
		}
		size-=DIRECT_ACCESS;
		uint32_t* indirect_block = (uint32_t*)malloc(BLOCK_SECTOR_SIZE);
		cached_read(inode, disk_inode.indirect,indirect_block);
		for(i=0; i<N_INDIRECT_POINTERS; i++){
			free_map_release(indirect_block[i], 1);
		}
		free_map_release(disk_inode.indirect, 1);
		free(indirect_block);
		size-=INDIRECT_ACCESS;
		uint32_t* double_indirect_block = (uint32_t*)malloc(BLOCK_SECTOR_SIZE);
		cached_read(inode, disk_inode.double_indirect,double_indirect_block);
		int c_size = size;
		int i,j;
		for(i=0; i<DIV_ROUND_UP(c_size, N_INDIRECT_POINTERS*BLOCK_SECTOR_SIZE); i++){
			cached_read(inode, double_indirect_block[i], buff);
			for(j=0; j<N_INDIRECT_POINTERS && j<DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); j++){
				free_map_release(buff[j], 1);
				
			}
			size-=BLOCK_SECTOR_SIZE*N_INDIRECT_POINTERS;
			free_map_release(double_indirect_block[i],1);
		}
		free_map_release(disk_inode.double_indirect, 1);
		free(double_indirect_block);
		free(buff);
		return;
	}
}
				
void cached_read(struct inode* inode, block_sector_t sector, const void *buffer){
	if(INODE_DEBUG) printf("cache_read: inode: %x sector: %d buffer: %x\n", inode, sector, buffer);
	
	traverse_buffcachelist();
	struct list_elem* e = NULL;
	for(e=list_begin(&buffcachelist); e!= list_end(&buffcachelist); e= list_next(e)){
		struct cached_block* cblock = list_entry(e, struct cached_block, elem);
		//printf("JMJMJMJMJMJMJMJMJMJMJMJMJM\n");
		if(cblock->sector == sector){
			memcpy(buffer, cblock->data, BLOCK_SECTOR_SIZE);
			//list_remove(e);
			//list_push_front(&buffcachelist, e);
			return;
		}
	}
	struct cached_block* free_buff = get_free_cache_buff();
	free_buff->inode = inode;
	free_buff->sector = sector;
	block_read(fs_device, sector, free_buff->data);
	memcpy(buffer, free_buff->data, BLOCK_SECTOR_SIZE);
}

void cached_write(struct inode* inode, block_sector_t sector, const void *buffer){
	if(INODE_DEBUG) printf("cache_write: inode: %x sector: %d buffer: %x\n", inode, sector, buffer);
	struct list_elem* e = NULL;
	
	for(e=list_begin(&buffcachelist); e!= list_end(&buffcachelist); e= list_next(e)){
		struct cached_block* cblock = list_entry(e, struct cached_block, elem);
		if(cblock->sector == sector){
			memcpy(cblock->data, buffer, BLOCK_SECTOR_SIZE);
			//list_remove(e);
			//list_push_front(&buffcachelist, e);
			return;
		}
	}	
	struct cached_block* free_buff = get_free_cache_buff();
	free_buff->inode = inode;
	free_buff->sector = sector;
	memcpy(free_buff->data, buffer, BLOCK_SECTOR_SIZE);
	cache_flush(inode, sector);
	//printf("cached_write(): buffer->data.direct[0]: %d\n", ((struct inode_disk*)(buffer))->direct[0]);
	//printf("cached_write(): free_buff->data.direct[0]: %d\n", ((struct inode_disk*)(free_buff->data))->direct[0]);
	//block_write(fs_device, sector, free_buff->data);
}

void cache_flush(struct inode* inode, block_sector_t sector){
	if(INODE_DEBUG) printf("cache_flush: inode: %x sector: %d\n", inode, sector);
	struct list_elem* e;
	
	if(sector==SECTOR_NONE){
		ASSERT(inode!=NULL);
		
		for(e=list_begin(&buffcachelist); e!= list_end(&buffcachelist); ){
			struct cached_block* cblock = list_entry(e, struct cached_block, elem);
			
			if(cblock->inode == inode){
				block_write(fs_device, cblock->sector, cblock->data);				
			}
			e = list_next(e);
			if(e==list_begin(&buffcachelist)){
				printf("cache_flush_over\n");
				return;
			}
		}
		return;
	}
	for(e=list_begin(&buffcachelist); e!= list_end(&buffcachelist); e= list_next(e)){
		struct cached_block* cblock = list_entry(e, struct cached_block, elem);
		if(cblock->sector == sector){
			//printf("cache_flush(): cblock->data ka direct[0]: %d\n", ((struct inode_disk*)(cblock->data))->direct[0]);
			block_write(fs_device, cblock->sector, cblock->data);				
			return;
		}
	}
	traverse_buffcachelist();
	printf("CACHE_FLUSH_OVER\n");
}

void cache_remove(struct inode* inode, block_sector_t sector){
	//if(INODE_DEBUG) ;
	printf("cache_remove() inode %x sector %ud\n", inode, sector);
	traverse_buffcachelist();
	struct list_elem* e;
	
	if(sector==SECTOR_NONE){
		ASSERT(inode!=NULL);
		struct list_elem* f;
		for(e=list_begin(&buffcachelist); e!= list_end(&buffcachelist); e=f){
			struct cached_block* cblock = list_entry(e, struct cached_block, elem);
			f = list_next(e);
			if(cblock->inode == inode){
				int idx = (cblock-buffcache)/sizeof(struct cached_block);
				ASSERT(idx>=0 && idx<N_BUFFERS);
				list_remove(e);
				traverse_buffcachelist();
				bitmap_set(cache_bitmap, idx, FREE);
				//memset(cblock, 0, sizeof(struct cached_block));
			}
			if(f==list_begin(&buffcachelist)){
				printf("cache_remove_over\n");
				return;
			}
		}
		return;		
	}
	else{
		for(e=list_begin(&buffcachelist); e!= list_end(&buffcachelist); e=list_next(e)){
			struct cached_block* cblock = list_entry(e, struct cached_block, elem);
			
			if(cblock->sector == sector){
				int idx = (cblock-buffcache)/sizeof(struct cached_block);
				ASSERT(idx>=0 && idx<N_BUFFERS);
				list_remove(e);
				traverse_buffcachelist();
				//memset(cblock, 0, sizeof(struct cached_block));
				bitmap_set(cache_bitmap, idx, FREE);
				return;
			}
		}
	}	
}

void traverse_buffcachelist(){
	//~ printf("traversing buffcachelist\n");
	//~ struct list_elem* e;
	//~ for(e=list_begin(&buffcachelist); e!= list_end(&buffcachelist); e= list_next(e)){
			//~ struct cached_block* cblock = list_entry(e, struct cached_block, elem);
			//~ printf("inode: %x sector: %d \n", cblock->inode, cblock->sector);
		//~ }
}
