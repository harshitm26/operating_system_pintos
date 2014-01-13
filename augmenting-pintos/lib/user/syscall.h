#ifndef __LIB_USER_SYSCALL_H
#define __LIB_USER_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include "filesys/directory.h"

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* Map region identifier. */
typedef int mapid_t;
#define MAP_FAILED ((mapid_t) -1)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0          /* Successful execution. */
#define EXIT_FAILURE 1          /* Unsuccessful execution. */

/* Projects 2 and later. */
void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
char* shared_memory_open(int size);
int shared_memory_close(void);
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

/* Project 3 and optionally project 4. */
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t);

/* Project 4 only. */
typedef unsigned int mode_t;
int mkdir(const char *pathname, mode_t mode); 
int readdir(unsigned int fd, struct old_linux_dirent* dirp, unsigned int count);
int chdir(const char *path); 
//~ int chdir (const char *dir);
//~ int mkdir (const char *dir);
//~ int readdir (int fd, char name[READDIR_MAX_LEN + 1]);
//~ bool isdir (int fd);
//~ int inumber (int fd);


/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/
pid_t fork ();
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/

#endif /* lib/user/syscall.h */
