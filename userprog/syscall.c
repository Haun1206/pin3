#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */


static void check_address(void* addr){
	/*if minimum needed check addr>(void)0x0*/
    if(!(is_user_vaddr(addr)))
        return exit(-1);
} 
void get_argument(struct intr_frame * f, int * arg, int count){
	ASSERT(1<=count && count<=6);
	switch(count){
		case 6:
			arg[5] = f->R.r9;
		case 5:
			arg[4] = f->R.r8;
		case 4:
			arg[3] = f->R.r10;
		case 3:
			arg[2] = f->R.rdx;
		case 2:
			arg[1] = f->R.rsi;
		case 1:
			arg[0] = f->R.rdi; 
	}
}
void halt(void){
	power_off();

}
void exit (int status){
	struct thread*t = thread_current();
	/*Tell the process descriptor the exit status*/
	t->status_exit = status;
	thread_exit();
}
pid_t fork(const char *thread_name){

}
int exec(const char *cmd_line){
	/*Make child process and get the process descriptor*/
	tid_t id = process_create_initd(cmd_line);
	struct thread * child = get_child_process(id);
	/*Wait until the child process is loaded*/
	sema_down(&(child->load_sema));
	/*If fail to load -> return -1 else, return the pid*/
	if(child->success_load ==false) 
		return -1;
	else 
		return id;
}
int wait(pid_t pid){
	int status  = process_wait(pid);
	return status;
}
bool create(const char*file, unsigned initial_size){
	return filesys_create(file, initial_size);
}
bool remove(const char *file){
	return filesys_remove(file);
}
int open (const char *file){
	struct file * res;
	int fd;
	lock_acquire(&file_lock);
	res = filesys_open(file);
	lock_release(&file_lock);
	if(res==NULL)
		fd = -1;
	ASSERT(fd!=1); /* stdoutput*/
	ASSERT(fd!=0); /*std input*/
	return fd;
}

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&file_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int64_t args[6];
	check_address(&f->rsp);
	thread_exit ();
	switch(f->R.rax)){
		case SYS_HALT:
			halt();
			break;
		
		case SYS_EXIT:
			get_argument(f,args,1);
			exit(args[0]);
			break;
		
		case SYS_FORK:
			break;

		case SYS_EXEC:
			break;
		
		case SYS_WAIT:
			break;
		
		case SYS_CREATE:
			break;
		
		case SYS_REMOVE:
			break;

		case SYS_OPEN:
			break;
		
		case SYS_FILESIZE:
			break;
		
		case SYS_READ:
			break;
		
		case SYS_WRITE:
			break;
		
		case SYS_SEEK:
			break;

		case SYS_TELL:
			break;
		
		case SYS_CLOSE:
			break;

		default:
	}
	printf("system call!\n");
	thread_exit();
}
