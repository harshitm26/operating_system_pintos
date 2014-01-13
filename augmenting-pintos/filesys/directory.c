#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#define PAGE_SIZE 1<<12


/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt, struct dir* parent, char* name)
{
  if(!inode_create (sector, (entry_cnt +2) * sizeof (struct dir_entry))){
	  return false;
  }else{
	  struct inode_disk* dir_inode = (struct inode_disk*) malloc(BLOCK_SECTOR_SIZE);
	  cached_read(NULL, sector, dir_inode);
	  dir_inode->type = TYPE_DIRECTORY;
	  block_sector_t b = dir_inode->direct[0];
	  cached_write(NULL, sector, dir_inode);
	  cache_flush(NULL, sector);
	  struct dir_entry* dblock = (struct dir_entry*) dir_inode;
	  cached_read(NULL, b, dblock);
	  
	  dblock[0].inode_sector = sector;
	  char name1[]= ".";
	  strlcpy(dblock[0].name, name, strlen(name1));
	  dblock[0].in_use = true;
	  
	  dblock[1].inode_sector = parent==NULL?ROOT_DIR_SECTOR:parent->inode->sector;
	  char name2[]= "..";
	  strlcpy(dblock[1].name, name, strlen(name2));
	  dblock[1].in_use = true;
	  bool success;
	  if(parent==NULL || dir_add(parent, name, sector, TYPE_DIRECTORY)) success = true;
	  cached_write(NULL, b, dblock);
	  cache_flush(NULL, b);
	  free(dir_inode);
	  return success;
  }
	  
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      if(strcmp("main", thread_current()->name)) insert_into_filetable(dir);
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
	  if(strcmp("main", thread_current()->name)) remove_from_filetable(dir);
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  printf("lookup(%x, %s, %x, %x)\n", dir, name, ep, ofsp);
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  printf("dir_lookup(%x, %s, %x)", dir, name, inode);
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL)){
	printf("Successfully found %s\n", name);
    *inode = inode_open (e.inode_sector);
  }else{
	 printf("Printing Files in root directory\n");
	 void * LIST;
	 fsutil_ls(LIST);
	 printf("Printed Files in root directory\n");
	 printf("Setting *inode NULL\n");
    *inode = NULL;
  }

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector, int type)
{
  printf("dir_add(%x, %s, %u, %d)\n", dir, name, inode_sector, type);
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, strlen(name)+1);
  e.inode_sector = inode_sector;
  //e.type=type;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  if(success){
	  ASSERT(lookup(dir, name, NULL, NULL));
  }
  else{
	  printf("Could not add to directory: %s\n", name);
  }
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}

void insert_into_filetable(struct dir* dir){
	struct dir** filetable = (struct dir**) thread_current()->filetable;
	int i;
	for(i=0; filetable[i]==0, i<PAGE_SIZE/sizeof(struct dir*); i++)
	;
	filetable[i] = dir;
}

void remove_from_filetable(struct dir* dir){
	struct dir** filetable = (struct dir**) thread_current()->filetable;
	int i;
	for(i=0; filetable[i]!=dir, i<PAGE_SIZE/sizeof(struct dir*); i++)
	;
	if(i<PAGE_SIZE/sizeof(struct dir*)) filetable[i] = 0;
}

unsigned int get_fd(struct dir* dir){
	int i;
	struct dir** filetable = (struct dir**) (thread_current()->filetable);
	for(i=0; filetable[i]!=dir, i<PAGE_SIZE/sizeof(struct dir*); i++)
	;
	if(i<PAGE_SIZE/sizeof(struct dir*) )return i;
}
