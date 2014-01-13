#include "lib/user/syscall.h"
#define PGSIZE 1<<12

int
main(int argc , char** argv ){
	int i=42, j;
	for(j=0; j<5; j++){
		printf("THIS IS A MESSAGE FROM USER PROCESS' MAIN i=%d\n", i);
	}
	
	int tid = fork();		//forking the process
	
	if(tid==0){
		//this is where child runs
		i++;		//i==43
		printf("CHILD SAYS: HELLO PAPA! i=%d\n", i);
		
		char program[] = "echo jeetesh vinit harshit 10314 10807 10290";
		char str[] = "CHILD: THIS IS A MESSAGE IN THE SHARED MEMORY\n";
		//opening a shared memory of one page size(in BYTES)
		char* shared = (char*)shared_memory_open(PGSIZE);
		
		//writing to the shared memory
		printf("%s", shared);
		
		strlcpy(shared, str, strlen(str)+1);
		//closing the shared memory
		shared_memory_close();
		
		printf("NOW EXECUTING \"echo jeetesh vinit harshit 10314 10807 10290\"\n");
		
		//executing the executable 'echo' with arguments as 'jeetesh vinit harshit 10314 10807 10290'
		exec(program);
	}
	else if(tid>0){
		//this is where parent enters after fork(), if successful
		
		
		
		i--;		//i==41
		printf("PARENT SAYS: HELLO CHILD tid=%d i=%d\n", tid, i);
		
		//opening a shared memory of one page size(in BYTES)
		char* shared = (char*)shared_memory_open(PGSIZE);

		char str[] = "PARENT: THIS IS A MESSAGE IN THE SHARED MEMORY\n";
		printf("RECEIVED %x AS SHARED MEM\n", shared);

		//writing to the shared memory
		strlcpy(shared, str, strlen(str)+1);
		wait(tid);
		printf("%s", shared);
		//closing the shared memory
		shared_memory_close();
	}
	else printf("COULD NOT CREATE CHILD :( \n");
	printf("PARENT COMPLETED\n");
	return 0;
}
