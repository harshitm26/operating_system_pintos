#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/kernel/bitmap.h"
#include "userprog/pagedir.h"
#include "threads/pte.h"
#include "threads/palloc.h"

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
#define EXCEPTION_DEBUG 0				//debug messages ON/OFF
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /* To implement virtual memory, delete the rest of the function
     body, and replace it with code that brings in the page to
     which fault_addr refers. */
  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  
  //~ kill (f);
  
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
  unsigned idx = get_free_frame_index(); //search for a free frame in framespace(using bitmap with locks)
  //bitmap_scan_and_flip(framebitmap, 0, 1, false);
  uint8_t* pg = pg_round_down(fault_addr);
  if(idx==BITMAP_ERROR){
	  //Page replacement algorithm can be implemented if the framespace gets full 
	  printf("Framespace full");
  }
  else{
	  if(EXCEPTION_DEBUG) printf("page_fault(): framespace idx: %d\n", idx);
	  
	  uint32_t* sdir = thread_current()->swapdir;
	  uint32_t* pdir = thread_current()->pagedir;
	  
	  uint32_t* spte = lookup_page_in_swapspace(sdir, fault_addr, false);	//looking for the fault address' table in swapspace
	  
	  uint32_t* fpte = lookup_page_in_framespace(pdir, fault_addr, false);	//looking for the fault address' table in framespace
	  
	  uint8_t* newpage = framespace + PGSIZE*idx;
	  
	  memset(newpage, 0, PGSIZE);		  
	  
	  if(fpte==NULL && spte==NULL){		//if the fault address' table not found in framespace and swapspace both
		  
		  if(EXCEPTION_DEBUG) printf("Table not found in both spaces\n");
		  
		  printf("framespace: pdir: %x pd_no: %x pde: %x *pde: %x\n", pdir, pd_no(fault_addr), pdir + pd_no(fault_addr), pdir[
		  pd_no(fault_addr)]);
		  
		  printf("swapspace: sdir: %x pd_no: %x pde: %x *pde: %x\n", sdir, pd_no(fault_addr), sdir + pd_no(fault_addr), sdir[pd_no(fault_addr)]);
		  
		  sdir[pd_no(fault_addr)] = pde_create(newpage);	//update the entry in swapdirectory
		  
		  if(EXCEPTION_DEBUG) printf("Page fault handled successfully\n");
		  return;
	  }
	  
	  if(fpte == NULL && spte!=NULL){	//if the table is found in swapspace
	  
		  if(EXCEPTION_DEBUG) printf("Table not found in framespace\n");
		  
		  uint32_t* pt = pde_get_pt(sdir[pd_no(fault_addr)]);	//get the page table entry of the fault_addr
		  
		  if(EXCEPTION_DEBUG) printf("sdir:%x pd_no: %x sdir:%x pt:%x pt_no(): %x\n", sdir, pd_no(fault_addr), sdir, pt, pt_no(fault_addr));
		  
		  if(EXCEPTION_DEBUG) printf("pde: %x *pde: %x pte: %x *pte: %x\n", sdir +pd_no(fault_addr), sdir[pd_no(fault_addr)], pt+pt_no(fault_addr), pt[pt_no(fault_addr)]);
		  
		  //bring the page into the framespace from swapspace
		  memcpy(newpage, pt, PGSIZE);
		  memset(pt, 0, PGSIZE);
		  
		  //update the entry in pagedirectory and swapdirectory
		  pdir[pd_no(fault_addr)] = pde_create(newpage);
		  sdir[pd_no(fault_addr)] = 0;
		  
		  int sidx = (((uint8_t*)pt)-swapspace)/PGSIZE;
		  set_swap_index(sidx, false);		//make the entry for the page taken away to be as free,in swapspace bitmap
		  //bitmap_set(swapbitmap, sidx, false);
		  if(EXCEPTION_DEBUG) printf("Page fault handled successfully\n");
		  return;
	  }
	  if(fpte!=NULL && spte==NULL){		//if the table is found in framespace
		  
		  if(*fpte==0){
			  if(EXCEPTION_DEBUG) if(!write) printf("Reading an all-zero area!\n");
			  if(EXCEPTION_DEBUG) printf("Page never allocated\n");
			  if(EXCEPTION_DEBUG) printf("*fpte=0\n");
			  //allot a new page in framespace if never allocated
			  *fpte = pte_create_user(newpage, true);
			  if(EXCEPTION_DEBUG) printf("*fpte=%x\n", *fpte);
			  if(EXCEPTION_DEBUG) printf("Page fault handled successfully\n");
			  return;
		  }
		  
		  if(1){	//bring page from swapspace to framespace 

			  if(EXCEPTION_DEBUG) printf("Bringing page frm swapspace\n");

			  uint8_t* page = pte_get_page(*fpte);	//pointer to the page in which fault_addr lies
			  if(EXCEPTION_DEBUG) printf("*fpte: %x page: %x\n", *fpte, page);
			  
			  //copy the page from swap to frame
			  memcpy(newpage, page, PGSIZE);
			  memset(page, 0, PGSIZE);
			  
			  unsigned sidx = (page-swapspace)/PGSIZE;
			  unsigned fidx = (page-framespace)/PGSIZE;
			  unsigned swapindex = (swapspace - (uint8_t*)PHYS_BASE)/PGSIZE;
			  if(EXCEPTION_DEBUG) printf("swapspace: %x framespace: %x page: %x\n", swapspace, framespace, page);
			  if(EXCEPTION_DEBUG) printf("swapindex: %u sidx : %u fidx: %u\n", swapindex, sidx, fidx);
			 
			  set_swap_index(sidx, false); //unset the bitmap entry for the moved page from swap
			  *fpte = pte_create_user(newpage, true);	//create page table entry for the moved page in framespace
			  if(EXCEPTION_DEBUG) printf("Page fault handled successfully\n");
			  return;
		  }
		  if(EXCEPTION_DEBUG) printf("Page fault handling failed\n");
		  kill(f);
	  }
	  if(EXCEPTION_DEBUG) printf("Page fault handling failed\n");
	  kill(f);		  
  } 
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
}

