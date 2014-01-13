#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/stdint.h"
#include "threads/interrupt.h"
#include "lib/debug.h"
#include "filesys/filesys.h"

void syscall_init (void);

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
int sys_write(int , const void*, unsigned);
int sys_exit(int);
int sys_fork(struct intr_frame* f);
void sys_wait(tid_t);
void sys_exec(char* command);
uint8_t* sys_shmopen(int size);
int sys_shmclose(char* ptr UNUSED);

struct fork_arg{
	uint32_t* pdir;			//pointer to pagedirectory
	uint32_t* sdir;			//pointer to swapdirectory
	struct intr_frame f;	//interrupt frame
};
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/*JVH Assignment 4
 */
typedef unsigned int mode_t;
int sys_mkdir(const char *pathname, mode_t mode); 
int sys_chdir(const char *path); 
int sys_readdir(unsigned int fd, struct old_linux_dirent* dirp, unsigned int count);


#endif /* userprog/syscall.h */
