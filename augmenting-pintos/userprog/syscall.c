#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "userprog/pagedir.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "userprog/process.h"


/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
#define STDOUT 1
#define SYSCALL_DEBUG 0			//debug msgs ON/OFF
#define START_ADDR 0x8000000
#define PGSIZE_IN_WORDS (PGSIZE >> 2)

static void syscall_handler (struct intr_frame *);
typedef int (*handler)(uint32_t, ...);
static handler syscall_map[25];				//map for syscalls
static int syscall_narg[25];				//map for number of arguments fro respective syscalls
int start_forked_process(struct fork_arg* arg);		//function to start forked process
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  
  syscall_map[SYS_WRITE] = (handler) sys_write;
  syscall_narg[SYS_WRITE] = 3;
  syscall_map[SYS_EXIT] = (handler) sys_exit;
  syscall_narg[SYS_EXIT] = 1;
  syscall_map[SYS_FORK] = (handler) sys_fork;
  syscall_narg[SYS_FORK] =0;
  syscall_map[SYS_EXEC] = (handler) sys_exec;
  syscall_narg[SYS_EXEC] =1;
  syscall_map[SYS_WAIT] = (handler) sys_wait;
  syscall_narg[SYS_WAIT] =1;
  syscall_map[SYS_SHMOPEN] = (handler) sys_shmopen;
  syscall_narg[SYS_SHMOPEN] =1;
  syscall_map[SYS_SHMCLOSE] = (handler) sys_shmclose;
  syscall_narg[SYS_SHMCLOSE] =0;
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  

  syscall_map[SYS_MKDIR] = (handler) sys_mkdir;
  syscall_narg[SYS_MKDIR] =2;
  syscall_map[SYS_READDIR] = (handler) sys_readdir;
  syscall_narg[SYS_READDIR] =3;
  syscall_map[SYS_CHDIR] = (handler) sys_chdir;
  syscall_narg[SYS_CHDIR] =1;


}

static void
syscall_handler (struct intr_frame *f) 
{
	
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/	
	if(SYSCALL_DEBUG) printf("SYSCALL START!\n");
	int res;
	int* stacktop = f->esp;
	if(!is_user_vaddr(stacktop)){
		printf("THREAD EXIT\n");
		thread_exit();
	}
	int narg = syscall_narg[*stacktop];		//number of arguments for the syscall
	handler h = syscall_map[*stacktop];		//handler function
	//printf("*stacktop: %d\n", *stacktop);
	switch(narg){
		case 0: if(h == (handler) sys_fork) res = h(f);		//if fork() is called, pass the interrupt frame to its syscall 
				else h(NULL); //sys_exit(-1);				//else no argument passed
				break;
		case 1: if(!is_user_vaddr(&stacktop[1])){
					if(SYSCALL_DEBUG) printf("arguments not in user virtual space\n");
					sys_exit(-1);
				}
				res = h(stacktop[1]);
				break;
		case 2: if(!(is_user_vaddr(&stacktop[2]))){
					if(SYSCALL_DEBUG) printf("arguments not in user virtual space\n");
					sys_exit(-1);
				}
					
				res= h(stacktop[1], stacktop[2]);
				break;
		case 3: if(!(is_user_vaddr(&stacktop[3]))){
					if(SYSCALL_DEBUG) printf("arguments not in user virtual space\n");
					sys_exit(-1);
				}
				res= h(stacktop[1], stacktop[2], stacktop[3]);
				break;
		case 4: if(!(is_user_vaddr(&stacktop[4]))){
					if(SYSCALL_DEBUG) printf("arguments not in user virtual space\n");
					sys_exit(-1);
				}
				res= h(stacktop[1], stacktop[2], stacktop[3], stacktop[4]);
				break;
		default:NOT_REACHED(); 
				break;
	}
	f->eax=res;				//saving the return value in eax
	if(SYSCALL_DEBUG) printf("SYSCALL END!\n");
	return;	
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
	
}

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
//the current process waits till the tid process exits
void sys_wait(tid_t tid){
	process_wait(tid);
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
//writes the BUFFER to the standard output of the given length
int sys_write(int fd, const void* buffer, unsigned length){
	if(fd == STDOUT && buffer!= NULL){
		putbuf(buffer, length);
		return 0;
	}
	else{
		return -1;
	}
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
//executes the 'cmd'(may even contain arguments)
void sys_exec(char* cmd){
	if(SYSCALL_DEBUG) printf("exec(): command: %s\n", cmd);
	
	char* command = palloc_get_page(0);
	strlcpy(command, cmd, strlen(cmd)+1);	//copying the command
	pagedir_destroy(thread_current()->pagedir);
	pagedir_destroy(thread_current()->swapdir);
	thread_current()->pagedir = NULL;		//pointing the current thread's swapdir & pagedir to NULL
	thread_current()->swapdir = NULL;	
	//printf("pagedir destroyed\n");
	
	//printf("swapdir destroyed\n");
	start_process(command);					//starting process
	NOT_REACHED();
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
//exit current thread
int sys_exit(int status){
  if(SYSCALL_DEBUG) printf("sys_exit() called\n");
  thread_exit ();
  NOT_REACHED();
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
//forks the process, returns the tid of child process to the parent process if successful, else -1	 
int sys_fork(struct intr_frame* f){
	
	if(SYSCALL_DEBUG) printf("sys_fork() called\n");
	if(SYSCALL_DEBUG) printf("PGSIZE in words: %d\n", PGSIZE_IN_WORDS);
	
	//pointers to current thread's page directories
	uint32_t* parent_pdir = thread_current()->pagedir;
	uint32_t* parent_sdir = thread_current()->swapdir;
	
	uint32_t *pde, *pte;		
	uint32_t* new_pdir = pagedir_create();	//create new pagedirectory
	uint32_t* new_sdir = palloc_get_page(PAL_ZERO);		//create new swapdirectory's page
	if(new_pdir==NULL) return -1;
	if(new_sdir==NULL) return -1;
	
	//setting and mapping all the pages from parent's pagedirectory to child's directory 

	for(pde = parent_pdir; pde < parent_pdir + 3*(PGSIZE_IN_WORDS>>2); pde++){
		//pde less than 3/4 of all virtual address space because user address space extends below 3GB (of total 4GB)
		if(*pde!=0){
			uint32_t* pt = pde_get_pt(*pde);
			int sidx_pt = get_free_swap_index(); //bitmap_scan_and_flip(swapbitmap, 0, 1, false);
			if(sidx_pt==BITMAP_ERROR){
				return -1;
			}
			uint8_t* newptable = swapspace + sidx_pt*PGSIZE;
			uint8_t* pt_vaddr = (pde-parent_pdir)<<22;		//page table's virtual address
			//printf("pde: %x parent_pdir: %x pt_vaddr: %x pdir + pd_no(pt_vaddr): %x \n", pde, parent_pdir, pt_vaddr, parent_pdir + pd_no(pt_vaddr));
			if(SYSCALL_DEBUG) printf("Adding map for table at vaddr: %x\n", pt_vaddr);
			
			//map the new pagetable at virtual address pt_vaddr
			if(!pagedir_set_page_swapspace(new_sdir, pt_vaddr, newptable, (int)(*pde) & PTE_W)){
				return -1;
			}
			if(SYSCALL_DEBUG) printf("pagetable allocated at pt_vaddr: %x\n", pt_vaddr);
			//copying all pagetable entries and the pages 
			for(pte = pt+1; pte < pt + PGSIZE_IN_WORDS; pte++){
				if(*pte!=0){
					int sidx_pg = get_free_swap_index(); //bitmap_scan_and_flip(swapbitmap, 0, 1, false);
					if(sidx_pg== BITMAP_ERROR){
						return -1;
					}
					uint8_t* newpage = swapspace + sidx_pg*PGSIZE;
					memcpy(newpage, pte_get_page(*pte), PGSIZE);	//copying the page
					uint8_t* pg_vaddr = ((pde-parent_pdir)<<22) + ((pte-pt)<<12);	//page's virtual address
					if(SYSCALL_DEBUG) printf("pg_vaddr: %x\n", pg_vaddr);
					if(SYSCALL_DEBUG) printf("Adding map for page at vaddr: %x\n", pg_vaddr);
					
					//adding map for page at virtual address vaddr
					if(!pagedir_set_page_swapspace(new_sdir, pg_vaddr, newpage, (int)(*pte) & PTE_W)){
						return -1;
					}
				}
			}
		}
	}
	
	//setting and mapping all the pages in the parent's swapdirectory to child's swapdirectory
	for(pde = parent_sdir; pde < parent_sdir + PGSIZE_IN_WORDS; pde++){
		if(*pde!=0){
			uint32_t* pt = pde_get_pt(*pde);
			int sidx_pt = get_free_swap_index(); //bitmap_scan_and_flip(swapbitmap, 0, 1, false);
			if(sidx_pt==BITMAP_ERROR){
				return -1;
			}
			uint8_t* newptable = swapspace + sidx_pt*PGSIZE;
			uint8_t* pt_vaddr = (pde-parent_pdir)<<22;
			if(SYSCALL_DEBUG) printf("Adding map for table at vaddr: %x\n", pt_vaddr);
			
			//map the new pagetable at virtual address pt_vaddr
			if(!pagedir_set_page_swapspace(new_sdir, pt_vaddr, newptable, (int)(*pde) & PTE_W)){
				return -1;
			}
			for(pte = pt+1; pte < pt + PGSIZE_IN_WORDS; pte++){
				if(*pte!=0){
					int sidx_pg = get_free_swap_index(); //bitmap_scan_and_flip(swapbitmap, 0, 1, false);
					if(sidx_pg== BITMAP_ERROR){
						return -1;
					}
					uint8_t* newpage = swapspace + sidx_pg*PGSIZE;
					memcpy(newpage, pte_get_page(*pte), PGSIZE);	//copying the page
					uint8_t* pg_vaddr = (pde-parent_pdir)<<22 + (pte-pt)<<12;
					if(SYSCALL_DEBUG) printf("Adding map for page at vaddr: %x\n", pt_vaddr);
					
					//adding map for page at virtual address vaddr
					if(!pagedir_set_page_swapspace(new_sdir, pg_vaddr, newpage, (int)(*pte) & PTE_W)){
						return -1;
					}
				}
			}
		}
	}
	struct fork_arg* arg = (struct fork_arg*) malloc(sizeof(struct fork_arg));
	arg->pdir = new_pdir;			//setting pointer to child's pagedir
	arg->sdir = new_sdir;			//setting pointer to child's swapdir
	
	memcpy(&arg->f, f, sizeof(struct intr_frame));	//copy the interrupt frame into arg's interrupt frame(to be passed to child process' thread_create()) 
	
	//create new thread for the child for which the start function is start_forked_process and structure arg is passed as en extra argument
	tid_t tid = thread_create(thread_name(), thread_current()->priority, start_forked_process, arg);
	return tid;
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
//starts the forked process, takes as argument the structure arg which has interrupt frame of parent,pagedirectories for the child 
int start_forked_process(struct fork_arg* arg){
	struct intr_frame _if;
	memcpy(&_if, &arg->f, sizeof(struct intr_frame));	//copy the interrupt frame of parent to child's interrupt frame
	
	//make the current thread's pagedirectory point to respective pagerdirectories
	thread_current()->pagedir = arg->pdir;				
	thread_current()->swapdir = arg->sdir;
	
	//return value for the child process is 0 if successful fork
	_if.eax = 0;
	
	//simulating as if the child process just re-ran after an interrupt
	asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&_if) : "memory");
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
//returns a pointer to the system-wide shared memory pages and adds the mappings in pagedirectory for the requested SIZE(SIZE is in bytes)
uint8_t* sys_shmopen(int size){

	if(SYSCALL_DEBUG) printf("sys_shmopen() called; size: %d\n", size);
	
	lock_acquire(&shmlock);		//acquire lock for shared memory
	if(size>SHM_PGS * PGSIZE){		//if the requested size exceeds the shared memory pages in the system
		return NULL;
	}
	
	int i, nPages = size/PGSIZE;	//number of pages to be mapped
	for(i=1; i<=nPages; i++)
		//mapping the shared memory pages in the current thread's page directory
		if(!pagedir_set_page_framespace(thread_current()->pagedir, START_ADDR - i*PGSIZE, shm_pages[nPages-i], true))
			return NULL;
			
	lock_release(&shmlock);			//release shared memory lock
	for(i=0; i<SHM_PGS; i++)
		if(SYSCALL_DEBUG) printf("shm_pages[%d]=%x\n", i, shm_pages[i]);
	return START_ADDR - nPages*PGSIZE;	//return the address from where the alloted shared memory starts
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
//closes the shared memory pages,returns 0 if successful. Here, it just removes the mappings for shared memory pages from the current thread's pagedirectory
int sys_shmclose(char* ptr UNUSED){
	if(SYSCALL_DEBUG) printf("sys_shmclose() called\n");
	int i;
	for(i=1; i<=thread_current()->nSharedMemPages; i++){
		uint32_t* pte = lookup_page_in_framespace(thread_current()->pagedir, START_ADDR - i*PGSIZE, false);
		if(pte!=NULL) *pte = 0;
	}
	return 0;
}
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

int sys_mkdir(const char *pathname, mode_t mode){
	char* path = (char*) malloc(strlen(pathname)+1);
	strlcpy(path, pathname, strlen(pathname)+1);
	char *token, *save;
	token = strtok_r(path, "/", &save);
	struct dir* prev = thread_current()->curdir;
	struct dir_entry* dirent;
	while(token!=NULL){
		if(!lookup(prev, token, &dirent, NULL)) break;
		if(prev != thread_current()->curdir) dir_close(prev);
		prev = dir_open(inode_open(dirent->inode_sector));
		token = strtok_r(NULL, "/", &save);
	}
	if(token==NULL){
		printf("Directory already exists!\n");
		return -1;
	}
	if(NULL != strtok_r(NULL, "/", &save)){
		printf("%s directory doesn't exist\n", token);
		return -1;
	}
	block_sector_t inode_sector;
	bool success = (free_map_allocate (1, &inode_sector)
					&& inode_create (inode_sector, INITIAL_DIRECTORY_ENTRIES)
					&& dir_add (prev, token, inode_sector, TYPE_DIRECTORY));
	if (!success && inode_sector != 0){
		free_map_release (inode_sector, 1);
		dir_close (prev);
		return -1;
	}
	else{
		dir_close(thread_current()->curdir);
		thread_current()->curdir = prev;
		return (int)get_fd(prev);
	}
}

int sys_readdir(unsigned int fd, struct old_linux_dirent* dirp, unsigned int count){
	char name[NAME_MAX+1];
	struct dir* d = (struct dir*)(thread_current()->filetable[fd]);
	if(!dir_readdir(d, name)){
		return 0;
	}
	else{
		strlcpy(dirp->d_name, name, strlen(name)+1);
		dirp->d_reclen = strlen(name)+1;
		struct dir* ptrdir = (struct dir*)(thread_current()->filetable[fd]);
		dirp->d_ino = ptrdir->inode->sector;
		off_t* off;
		lookup(ptrdir, name, NULL, &off);
		dirp->d_off = *off;
		return 1;
	}
}
	
int sys_chdir(const char *pathname){
	char* path = (char*) malloc(strlen(pathname)+1);
	strlcpy(path, pathname, strlen(pathname)+1);
	char *token, *save;
	token = strtok_r(path, "/", &save);
	struct dir* prev = thread_current()->curdir;
	struct dir_entry* dirent;
	while(token!=NULL){
		if(!lookup(prev, token, &dirent, NULL)) break;
		if(prev != thread_current()->curdir) dir_close(prev);
		struct inode* inode= inode_open(dirent->inode_sector);
		prev = dir_open(inode);
		token = strtok_r(NULL, "/", &save);
	}
	if(token!=NULL){
		printf("%s directory doesn't exist\n", token);
		return -1;
	}
	if(token==NULL){
		dir_close(thread_current()->curdir);
		dir_open(prev);
		return get_fd(prev);
	}
}
