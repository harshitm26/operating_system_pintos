#include "userprog/pagedir.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "lib/kernel/bitmap.h"
#include "threads/thread.h"

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  
#define PAGEDIR_DEBUG 0				//debug msgs ON/OFF
#define SHM_PGS 2					//Number of pages for system-wide shared memory
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  

static uint32_t *active_pd (void);
static void invalidate_pagedir (uint32_t *);

/* Creates a new page directory that has mappings for kernel
   virtual addresses, but none for user virtual addresses.
   Returns the new page directory, or a null pointer if memory
   allocation fails. */
uint32_t *
pagedir_create (void) 
{
  uint32_t *pd = palloc_get_page (0);
  if (pd != NULL)
    memcpy (pd, init_page_dir, PGSIZE);
  return pd;
}

/* Destroys page directory PD, freeing all the pages it
   references. */
void
pagedir_destroy (uint32_t *pd) 
{
  uint32_t *pde;

  if (pd == NULL)
    return;

  ASSERT (pd != init_page_dir);

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  
//freeing all the pages referenced by this page directory 
  for (pde = pd; pde < pd + pd_no (PHYS_BASE); pde++){
    if (*pde!=0) //(*pde & PTE_P)		//if the pagetable address referenced by pagedir entry is not null   
      {
        uint32_t *pt = pde_get_pt (*pde);
        uint32_t *pte;
        
        //for each entry in the page tables,freeing the corresponding pages
        for (pte = pt; pte < pt + PGSIZE / sizeof *pte; pte++){
			
          if (*pte!=0){		//if the page is not empty 
            
            uint8_t* page = pte_get_page(*pte);
            
            if(is_in_framespace(page)){		//freeing the page from framespace if it is in the framespace
				
				int fidx = (page-framespace) / PGSIZE;
				set_frame_index(fidx, false);	//unset the correspoding entry in framespace's bitmap
				memset(page, 0, PGSIZE);
				
			}
			else if(is_in_swapspace(page)){ //freeing the page from swapspace if it is in the swapspace
			
				int sidx = (page-swapspace) / PGSIZE;
				set_swap_index(sidx, false);	//unset the correspoding entry in swapspace's bitmap	
				memset(page, 0, PGSIZE);
				
			}
		  }
		}
        
        uint8_t* ptable = pde_get_pt(*pde);	//pointer to the pagetable pointed by the pagedirectory entry
        
        if(is_in_framespace(ptable)){	//if the pagetable page is in framespace,free it from there
			
				int fidx = (ptable-framespace) / PGSIZE;
				set_frame_index(fidx, false);	//unset the correspoding entry in framespace's bitmap
				memset(ptable, 0, PGSIZE);
				
		}
		else if(is_in_swapspace(ptable)){	//if the pagetable page is in swapspace,free it from there
		
				int sidx = (ptable-swapspace) / PGSIZE;
				set_swap_index(sidx, false);	//unset the correspoding entry in swapspace's bitmap
				memset(ptable, 0, PGSIZE);
				
		}
    }
  }  
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
      
  //palloc_free_page (pd);		//free the page for pagedirectory
}

/* Returns the address of the page table entry for virtual
   address VADDR in page directory PD.
   If PD does not have a page table for VADDR, behavior depends
   on CREATE.  If CREATE is true, then a new page table is
   created and a pointer into it is returned.  Otherwise, a null
   pointer is returned. */
uint32_t *
lookup_page (uint32_t *pd, const void *vaddr, bool create)
{
  uint32_t *pt, *pde;

  ASSERT (pd != NULL);

  /* Shouldn't create new kernel virtual mappings. */
  ASSERT (!create || is_user_vaddr (vaddr));

  /* Check for a page table for VADDR.
     If one is missing, create one if requested. */
  pde = pd + pd_no (vaddr);
  uint8_t* pg = NULL;
  if (*pde == 0) 
    {
      if (create)
        {
          pt = palloc_get_page (PAL_ZERO);
          if (pt == NULL) 
          return NULL; 
      
          *pde = pde_create (pg);
        }
      else
        return NULL;
    }

  /* Return the page table entry. */
  pt = pde_get_pt (*pde);
  return &pt[pt_no (vaddr)];
}

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
//Returns the address of the page table entry for virtual address VADDR in framespace's page directory PD.
//If PD does not have a page table for VADDR, behavior depends on CREATE.  If CREATE is true, then a new page table is created and a pointer into it is returned.  Otherwise, a null pointer is returned.
uint32_t *
lookup_page_in_framespace (uint32_t *pd, const void *vaddr, bool create)
{
  uint32_t *pt, *pde;

  ASSERT (pd != NULL);

  /* Shouldn't create new kernel virtual mappings. */
  ASSERT (!create || is_user_vaddr (vaddr));

  /* Check for a page table for VADDR.
     If one is missing, create one if requested. */
  pde = pd + pd_no (vaddr);
  uint8_t* pg = NULL;
  if (*pde == 0) 
    {
      if (create)
        {
		  int idx = get_free_frame_index();			//get a free frame 
		  //bitmap_scan_and_flip(framebitmap, 0, 1, false);
		  
		  if(idx == BITMAP_ERROR) return NULL;		//if no bitmap entry is false(i.e. no free page in swapspace),return NULL, here page replacement may be implemented	
		  if(PAGEDIR_DEBUG) printf("look_up_in_framespace() idx acquired: %d\n", idx);
          
          pg = framespace + idx*PGSIZE;
          memset(pg, 0, PGSIZE);
			
          *pde = pde_create (pg);
        }
      else
        return NULL;
    }

  /* Return the page table entry. */
  pt = pde_get_pt (*pde);
  return &pt[pt_no (vaddr)];	//return the address of the page table entry
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/


/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
/* Adds a mapping in page directory PD for framespace from user virtual page
   UPAGE to the physical frame identified by kernel virtual
   address KPAGE.
   UPAGE must not already be mapped.
   If WRITABLE is true, the new page is read/write;
   otherwise it is read-only.
   Returns true if successful, false if memory allocation
   failed. */
// i.e. set page in framespace
bool
pagedir_set_page_framespace (uint32_t *pd, void *upage, void *kpage, bool writable)
{	
  uint32_t *pte;

  ASSERT (pg_ofs (upage) == 0);
  ASSERT (pg_ofs (kpage) == 0);
  ASSERT (is_user_vaddr (upage));
  ASSERT (vtop (kpage) >> PTSHIFT < init_ram_pages);
  ASSERT (pd != init_page_dir);

  pte = lookup_page_in_framespace (pd, upage, true);	//look for the page table entry for user virtual page UPAGE in framespace

  if (pte != NULL) 
    {
      ASSERT ((*pte & PTE_P) == 0);
      *pte = pte_create_user (kpage, writable);			//store the PTE that points to that page
      return true;
    }
  else
    return false;
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
/* Adds a mapping in swapspace page directory SD for swapspace from user virtual page
   UPAGE to the swap page identified by kernel virtual
   address KPAGE.
   UPAGE must not already be mapped.
   If WRITABLE is true, the new page is read/write;
   otherwise it is read-only.
   Returns true if successful, false if memory allocation
   failed. */
// i.e. set page in swapspace
bool
pagedir_set_page_swapspace (uint32_t *sd, void *upage, void *kpage, bool writable)
{
  uint32_t *pte;

  ASSERT (pg_ofs (upage) == 0);
  ASSERT (pg_ofs (kpage) == 0);
  ASSERT (is_user_vaddr (upage));
  ASSERT (vtop (kpage) >> PTSHIFT < init_ram_pages);
  ASSERT (sd != init_page_dir);

  pte = lookup_page_in_swapspace (sd, upage, true);		//look for the page table entry for user virtual page UPAGE in swapspace
  
  if (pte != NULL) 
    {
      ASSERT ((*pte & PTE_P) == 0);
      *pte = pte_create_user (kpage, writable);			//store the PTE that points to that page
      
      if(PAGEDIR_DEBUG) printf("pagedir_set_page_swapspce() pte: %x *pte: %x\n", pte, *pte);
      
      //~ printf("pte: %x *pte: %x pte_create_user: %x\n", pte, *pte, pte_create_user (kpage, writable));
      //~ hex_dump(0, pte, 4, 1);
      //~ hex_dump(0, pg_round_down(pte), PGSIZE, 1);
      
      return true;		//true if successful
    }
  else
    return false;
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/



/* Looks up the physical address that corresponds to user virtual
   address UADDR in PD.  Returns the kernel virtual address
   corresponding to that physical address, or a null pointer if
   UADDR is unmapped. */
void *
pagedir_get_page (uint32_t *pd, const void *uaddr) 
{
  uint32_t *pte;

  ASSERT (is_user_vaddr (uaddr));
  
  pte = lookup_page (pd, uaddr, false);
  if (pte != NULL && (*pte & PTE_P) != 0)
    return pte_get_page (*pte) + pg_ofs (uaddr);
  else
    return NULL;
}

/* Marks user virtual page UPAGE "not present" in page
   directory PD.  Later accesses to the page will fault.  Other
   bits in the page table entry are preserved.
   UPAGE need not be mapped. */
void
pagedir_clear_page (uint32_t *pd, void *upage) 
{
  uint32_t *pte;

  ASSERT (pg_ofs (upage) == 0);
  ASSERT (is_user_vaddr (upage));

  pte = lookup_page (pd, upage, false);
  if (pte != NULL && (*pte & PTE_P) != 0)
    {
      *pte &= ~PTE_P;
      invalidate_pagedir (pd);
    }
}

/* Returns true if the PTE for virtual page VPAGE in PD is dirty,
   that is, if the page has been modified since the PTE was
   installed.
   Returns false if PD contains no PTE for VPAGE. */
bool
pagedir_is_dirty (uint32_t *pd, const void *vpage) 
{
  uint32_t *pte = lookup_page (pd, vpage, false);
  return pte != NULL && (*pte & PTE_D) != 0;
}

/* Set the dirty bit to DIRTY in the PTE for virtual page VPAGE
   in PD. */
void
pagedir_set_dirty (uint32_t *pd, const void *vpage, bool dirty) 
{
  uint32_t *pte = lookup_page (pd, vpage, false);
  if (pte != NULL) 
    {
      if (dirty)
        *pte |= PTE_D;
      else 
        {
          *pte &= ~(uint32_t) PTE_D;
          invalidate_pagedir (pd);
        }
    }
}

/* Returns true if the PTE for virtual page VPAGE in PD has been
   accessed recently, that is, between the time the PTE was
   installed and the last time it was cleared.  Returns false if
   PD contains no PTE for VPAGE. */
bool
pagedir_is_accessed (uint32_t *pd, const void *vpage) 
{
  uint32_t *pte = lookup_page (pd, vpage, false);
  return pte != NULL && (*pte & PTE_A) != 0;
}

/* Sets the accessed bit to ACCESSED in the PTE for virtual page
   VPAGE in PD. */
void
pagedir_set_accessed (uint32_t *pd, const void *vpage, bool accessed) 
{
  uint32_t *pte = lookup_page (pd, vpage, false);
  if (pte != NULL) 
    {
      if (accessed)
        *pte |= PTE_A;
      else 
        {
          *pte &= ~(uint32_t) PTE_A; 
          invalidate_pagedir (pd);
        }
    }
}

/* Loads page directory PD into the CPU's page directory base
   register. */
void
pagedir_activate (uint32_t *pd) 
{
  if (pd == NULL)
    pd = init_page_dir;

  /* Store the physical address of the page directory into CR3
     aka PDBR (page directory base register).  This activates our
     new page tables immediately.  See [IA32-v2a] "MOV--Move
     to/from Control Registers" and [IA32-v3a] 3.7.5 "Base
     Address of the Page Directory". */
  asm volatile ("movl %0, %%cr3" : : "r" (vtop (pd)) : "memory");
}

/* Returns the currently active page directory. */
static uint32_t *
active_pd (void) 
{
  /* Copy CR3, the page directory base register (PDBR), into
     `pd'.
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 3.7.5 "Base Address of the Page Directory". */
  uintptr_t pd;
  asm volatile ("movl %%cr3, %0" : "=r" (pd));
  return ptov (pd);
}

/* Seom page table changes can cause the CPU's translation
   lookaside buffer (TLB) to become out-of-sync with the page
   table.  When this happens, we have to "invalidate" the TLB by
   re-activating it.

   This function invalidates the TLB if PD is the active page
   directory.  (If PD is not active then its entries are not in
   the TLB, so there is no need to invalidate anything.) */
static void
invalidate_pagedir (uint32_t *pd) 
{
  if (active_pd () == pd) 
    {
      /* Re-activating PD clears the TLB.  See [IA32-v3a] 3.12
         "Translation Lookaside Buffers (TLBs)". */
      pagedir_activate (pd);
    } 
}


/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
//Returns the address of the page table entry for virtual address VADDR in swapspace's page directory SD.
//If SD does not have a page table for VADDR, behavior depends on CREATE.  If CREATE is true, then a new page table is created and a pointer into it is returned.  Otherwise, a null pointer is returned.
uint32_t *
lookup_page_in_swapspace (uint32_t *sd, const void *vaddr, bool create)
{
  uint32_t *pt, *pde;

  ASSERT (sd != NULL);

  // Shouldn't create new kernel virtual mappings. 
  ASSERT (!create || is_user_vaddr (vaddr));

  // Check for a page table for VADDR.
  //   If one is missing, create one if requested. 
  uint8_t* pg = NULL;
  pde = sd + pd_no (vaddr);
  if(PAGEDIR_DEBUG) printf("pde=%x *pde=%x in look_up_in_swapspace()\n", pde, *pde);
  
  if (*pde == 0) 
    {
      if (create)
        {
		  int idx = get_free_swap_index(); //bitmap_scan_and_flip(swapbitmap, 0, 1, false);
		  
		  if(idx == BITMAP_ERROR) return NULL;	//if no bitmap entry is false(i.e. no free page in swapspace),return NULL, here page replacement may be implemented	
		  
		  if(PAGEDIR_DEBUG) printf("look_up_in_swapspace() idx acquired: %d\n", idx);
          pg = swapspace + idx*PGSIZE;
          memset(pg, 0, PGSIZE);
  
          *pde = pde_create (pg);	//create page directory entry for this page 
          
        }
      else
        return NULL;
    }

  pt = pde_get_pt (*pde);

  if(PAGEDIR_DEBUG) printf("lookup_page_in_swapspace() pte: %x *pte: %x\n", pt+pt_no(vaddr), pt[pt_no (vaddr)]);

  return &pt[pt_no (vaddr)];	//return the address of the page table entry
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/


/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
unsigned get_free_frame_index(){
	//get the index of the free page in framespace
	lock_acquire(&framelock);
	int idx = bitmap_scan_and_flip(framebitmap, 0, 1, false);
	lock_release(&framelock);
	return idx;
}

unsigned get_free_swap_index(){
	//get the index of the free page in swapspace
	lock_acquire(&swaplock);
	int idx = bitmap_scan_and_flip(swapbitmap, 0, 1, false);
	lock_release(&swaplock);
	return idx;
}

void set_frame_index(unsigned idx, bool value){
	//sets the value of the page in framespacebitmap
	lock_acquire(&framelock);
	bitmap_set(framebitmap, idx, value);
	lock_release(&framelock);
}

void set_swap_index(unsigned idx, bool value){
	//sets the value of the page in swapspacebitmap
	lock_acquire(&swaplock);
	bitmap_set(swapbitmap, idx, value);
	lock_release(&swaplock);
}

bool is_in_swapspace(uint8_t* vaddr){
	//whether the virtual address VADDR lies in swapspace's range or not
	return vaddr>=swapspace && vaddr < swapspace+SWAP_PAGES;
}

bool is_in_framespace(uint8_t* vaddr){
	//whether the virtual address VADDR lies in framespace's range or not
	return vaddr>=framespace && vaddr < framespace+N_FRAMES;
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
