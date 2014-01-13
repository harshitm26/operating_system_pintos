#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "threads/pte.h"
#include "userprog/syscall.h"

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
#define PROCESS_DEBUG 0			//debug msgs ON/OFF
#define MAX_N_ARGS 32		//maximum number of arguments that can be passed to an executable
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);



//	 Starts a new thread running a user program loaded from
//   FILENAME extracted from COMMAND string.  The new thread may be scheduled (and may even exit)
//   before process_execute() returns.  Returns the new process's
//   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *command) 
{
  tid_t tid;
  char c[] = " ";
     
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
  char* copy_command = palloc_get_page (0);			
  
  if (copy_command == NULL)
    return TID_ERROR;

  strlcpy (copy_command, command, PGSIZE);			//get a copy of COMMAND(which includes executable's name &  list of arguments)	Otherwise there's a race between the caller and load().
  
  if(PROCESS_DEBUG) printf("command: %x, *command: %s\n", command, command);
  
  char* first_space = strpbrk(command, c);	//take the pointer to the first space in 'command'
  if(first_space!=NULL){
	  *first_space = '\0';					//mark the end of string in 'command' after the executable name
	  //~ int nchars = first_space-command;
	  //~ strlcpy (prog_name, command, nchars);
	  //~ prog_name[nchars]='\0';
  }
  
  // Create a new thread to execute the executable(which is now given by 'command'),passing 'copy_command' as auxiliary data 
  tid = thread_create (command, PRI_DEFAULT, start_process, copy_command);
  
  if (tid == TID_ERROR)
    palloc_free_page (copy_command); 
  
  if(PROCESS_DEBUG) printf("New thread's tid: %d",tid);  
  return tid;		//return the tid of the new thread successfully created
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
  
}

/* A thread function that loads a user process and starts it
   running. */
void
start_process (void *command)
{
  if(PROCESS_DEBUG) printf("start_process(): command: %s\n", command);
  //char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  success = load ((const char*)command, &if_.eip, &if_.esp);
  /* If load failed, quit. */
  //palloc_free_page (command);
  if( PROCESS_DEBUG) printf("Start process success %d\n", success?1:0);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.
*/
int
process_wait (tid_t child_tid) 
{
  struct thread* t = get_thread(child_tid);

  if(t == NULL) return ENOTFND;			//if the thread does not exist return not found error
  
  if(t->waiter != NULL) return EALREADY;	//if 't' already has a waiter return error
  
  t->waiter = thread_current();			//set the current thread as  the waiter of 't' 
  
  enum intr_level old_level = intr_disable();
  
  thread_block();			//block current thread until the child exits
  
  intr_set_level(old_level);  
  return 0;
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/* Free the current process's resources. */

void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
    
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
  if(thread_current()->waiter != NULL) thread_unblock(thread_current()->waiter);	//unblock the waiter of this thread,if any
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char* arg_list);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *command, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;


/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
  //char* command = (char*)malloc(sizeof(char)*(strlen(cmd)+1));
  //strlcpy(command, cmd, strlen(cmd)+1);
  
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  t->filetable = palloc_get_page(PAL_USER | PAL_ASSERT | PAL_ZERO);
  t->curdir = dir_open_root();
  
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  
  t->swapdir = palloc_get_page(PAL_ASSERT | PAL_ZERO);		//get a free page from kernel pool for the swapdirectory of this thread

  char c = ' ';
  
  if(PROCESS_DEBUG) printf("load(): command: %x *command: %s\n", command, command);
  
  char* first_space = strchr(command, c);	//Finds and returns the first occurrence of c in command

  char* prog_name = palloc_get_page(PAL_ZERO);		//get a free page for program name(executable name)
  if(PROCESS_DEBUG) printf("command: %s\n", command);
  
  strlcpy(prog_name, command, first_space-command+1);	//copy the executable name to prog_name
  
  if(PROCESS_DEBUG) printf("load(): command: %s prog_name: %s\n", command, prog_name);

  file = filesys_open (prog_name);		//open the executable
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", prog_name);
      goto done; 
    }
  palloc_free_page(prog_name);
  
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", prog_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
		
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
        
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
        
          if (validate_segment (&phdr, file)) 
            {
				
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, command))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
	//~ printf("\n");
	//~ hex_dump(0, (const void*)0xbffffff0, 200, 1);
 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  //hex_dump(0, t->pagedir, 4*1024, 0);
  //printf("sdir in load() %x\n", thread_current()->swapdir);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;

  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */

  if (phdr->p_vaddr < PGSIZE)
    return false;
	//printf("HERE!!!!!!!!!!!!!!!!!!!!!!!!!! %d", phdr->p_vaddr);    
  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
  uint32_t* sdir = thread_current()->swapdir;		//get the pointer to current thread's swapdirectory
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
      //get index of free swap page
      int idx = get_free_swap_index(); //bitmap_scan_and_flip(swapbitmap, 0, 1, false);
      
      if(idx==BITMAP_ERROR) return false;	//no page free,page replacement can be implemented
      
      if(PROCESS_DEBUG) printf("load_segment() idx: %d\n", idx);
      //~ uint8_t *kpage = palloc_get_page (PAL_USER);
      
      uint8_t* kpage = swapspace + PGSIZE*idx;	//pointer to the free page in swapspace
      if (kpage == NULL){
		  palloc_free_page(kpage);
		  pagedir_destroy(sdir);
		  return false;
	  }

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          pagedir_destroy(sdir);
          return false; 
        }
        //hex_dump(0, kpage, PGSIZE, 0);
      memset (kpage + page_read_bytes, 0, page_zero_bytes);		//fill the remaining space in page with zeroes
      
      if(PROCESS_DEBUG) printf("sdir:%x\n", sdir);
      if(PROCESS_DEBUG) printf("load_segment(): Adding map: %x : %x\n", upage, kpage);
      
      if(pagedir_set_page_swapspace(sdir, upage, kpage, writable)==false){	//set the page in swapspace(add mappings)
		  palloc_free_page (kpage);
		  pagedir_destroy(sdir);
		  return false;
	  }
	  if(PROCESS_DEBUG) printf("upage: %x kpage: %x pde: %x pte: %x\n", upage, kpage, sdir[pd_no(upage)], pde_get_pt(sdir[pd_no(upage)])[pt_no(upage)]);
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/


      /* Add the page to the process's address space. */
      //~ if (!install_page (upage, kpage, writable)) 
        //~ {
          //~ palloc_free_page (kpage);
          //~ palloc_free_page(sdir);
          //~ return false; 
        //~ }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
	//printf("sdir in load_segment() %x\n", sdir);
  return true;
}


/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
static bool
setup_stack (void **esp, char* arg_list) 	//arg_list contains the list of arguments passed to the executable
{

  //hex_dump(0, init_page_dir, PGSIZE, 1);
  //hex_dump(0, arg_list, 20, 1);
  //~ uint8_t *kpage;
  bool success = false;
  //get free swapspace's page's index
  int idx = get_free_swap_index(); //bitmap_scan_and_flip(swapbitmap, 0, 1, false);
  
  if(idx==BITMAP_ERROR) return false;		//swapspace full,page replacement may be done
  
  if(PROCESS_DEBUG) printf("setup_stack() idx: %d\n", idx);
  //~ uint8_t *kpage = palloc_get_page (PAL_USER);
  
  uint8_t* kpage = swapspace + PGSIZE*idx;

  //~ kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
	  if(PROCESS_DEBUG) printf("setup_stack(): Adding map: %x : %x\n", ((uint8_t*) PHYS_BASE - PGSIZE), kpage);
	  //add the mapping in the pagedirectory of swapspace:
      success = pagedir_set_page_swapspace(thread_current()->swapdir, ((uint8_t*) PHYS_BASE - PGSIZE), kpage, true);
      if (success){
		*esp = PHYS_BASE;
		int i;
		char delim[] = " ";
		char* saved_position = NULL, *token;
		char* argv[MAX_N_ARGS];
		
		//breaking the arg_list into tokens(representing arguments) separated by spaces and decrementing the stack pointer from PHYS_BASE as per it and storing the arguments in the stack
		for(i=0, token = strtok_r(arg_list, delim, &saved_position); token != NULL; token = strtok_r(NULL, delim, &saved_position), i++){
			//printf("token: %s\n", token);
			*esp = *esp - strlen(token) -1;
			argv[i]=*esp;
			strlcpy(*esp, token, strlen(token)+1);
			//printf("**esp: %s\n", *esp);
		}
        argv[i]=NULL;		//mark the end of arguments by NULL

        *esp = (uint32_t)(*esp) & ((-1)<<2);	//making the stack pointer word-aligned
        
        //printf("*esp: %x\n", *esp);
        
        *esp = *esp - (i+1)*sizeof(uintptr_t);
        memcpy(*esp, argv, (i+1)*sizeof(uintptr_t));		//save the pointer to arguments,i.e. argv[0],argv[1]..... (char*)
        
        *((int**)(*esp-sizeof(uintptr_t))) = *esp;			//for pointer to argv (char**)
        *esp = *esp - sizeof(uint32_t);
        *esp = *esp - sizeof(uint32_t);
        
        //int* s = (int*)(*esp);
        
        *((int **)*esp) = i;								//argc (int)
        *esp = *esp - sizeof(uint32_t);						//for return address (void *)
        //s = (int*)(*esp);
        //*s = 0xcafebead;
        *((int **)*esp) = 0xCAFEBEAD;						//marking the end of stack by some random magic number
        if(PROCESS_DEBUG) printf("Stack set up successfullly at *esp: %x\n", *esp);
        if(PROCESS_DEBUG) hex_dump(0, *esp, PHYS_BASE - *esp, 1);
	  }
      else{
		if(PROCESS_DEBUG) printf("Could not setup stack!\n");
		set_swap_index(idx, false);
        //palloc_free_page (kpage);
	  }
    }
    //~ int i=0;
  //~ for(i =2; i<50; i++){
	//~ kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	//~ install_page(((uint8_t *) PHYS_BASE) - i*PGSIZE, kpage, true);
	//~ }
  //~ 
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

