#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void start_process (void *command);

/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  
enum{
	ENOTFND,	//not found error
	EALREADY	//already exists error
};
/*JVH Assignment 3 -----------------------------------------------------------------------------HVJ*/  

#endif /* userprog/process.h */
