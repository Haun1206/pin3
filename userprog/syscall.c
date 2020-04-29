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
void halt (void);
void exit (int status);
pid_t fork(const char *thread_name);
int exec (const char *cmd_line);
int wait (pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close(int fd);

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

struct lock file_lock;	

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
void halt(void){
	power_off();

}
void exit (int status){
	struct thread*t = thread_current();
	/*Tell the process descriptor the exit status*/
	t->status_exit = status;
	thread_exit();
}
int fork(const char *thread_name){

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
int wait(int pid){
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
	/*  Open the file and give the file descriptor
		Ret; the file descriptor
	*/
	struct file * res;
	lock_acquire(&file_lock);
	res = filesys_open(file);
	lock_release(&file_lock);
	if(res==NULL)
		return -1;
	int fd = process_add_file(res);
	return fd;
}
int filesize(int fd){
	/*Find the file with the fd and return the length of the file*/
	struct *f = process_get_file(fd);
	if(f==NULL)
		return -1;
	int size = file_length(f);
	return size;

}
int read(int fd, void *buffer, unsigned size){
	/*	Read opeeration might occur concurrently, thus we use locks
		find the file with fd and if fd=0 (input)-> save the keyboard input on buffer, and return the saved size
		if not zero -> read the file as much as the given size
	*/
	char* rd_buf = (char *)buffer;
	int count= 0;
	struct file* f;
	lock_acquire(&file_lock);
	if(fd==STDIN_FILENO){
		/*Save input to keyboard->use input_getc (input.h)->one by one*/
		rd_buf[count] = input_getc();
		/*Until the size given + if it is enter, we stop*/
		while(count<size && rd_buf[count]!='\n'){
			count +=1;
			rd_buf[count] = input_getc();
		}
		rd_buf[count] = '\0';
	}else{
		if((f=process_get_file(fd))!=NULL)
			count = file_read(f,buffer,size);
	}
	lock_release(&file_lock);
	return count;
}
int write (int fd, const void *buffer, unsigned size){
	/* In order to prevent concurrency, use locks. When we deal with files.
	find the file by fd, and if it is fd=Output signal, we print the buffer
	else, we write it of the buffer size to the file
	*/
	int count = 0;
	struct file* f;
	lock_acquire(&file_lock);
	if(fd==STDOUT_FILENO){
		putbuf((const char *)buffer, size);
		count = size;
	}else{
		if((f=process_get_file(fd)) != NULL)
			count = file_write(f, (const void *)buffer, size);
	}
	lock_release(&file_lock);
	return count;
}
void seek (int fd, unsigned position){
	/*move the offset as the amount of position/Find file by fd*/
	struct file *f;
	if((f=process_get_file(fd))!=NULL)
		file_seek(f,position);
}
unsigned tell (int fd){
	/*tell the offset*/
	struct file *f;
	unsigned offset = 0;
	if((f=process_get_file(fd))!=NULL)
		offset = file_tell(f);
	return offset;
}
void close(int fd){
	/*close the file of the fd and entry initialize*/
	struct file *f;
	if((f=process_get_file(fd)) !=NULL){
		file_close(f);
		struct thread *t = thread_current();
		t->fd_table[fd] =NULL;
	}
}


/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int64_t args[6];
	check_address(&f->rsp);
	switch(f->R.rax){
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
			get_argument(f,args,1);
			
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
			break;
	}
	printf("system call!\n");
	thread_exit();
}
