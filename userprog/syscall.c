#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <list.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/mmu.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "vm/vm.h"
#include "vm/file.h"

#include "intrinsic.h"

static void check_addr(void* addr);
/*void get_argument(struct intr_frame * f, int * arg, int count);*/
static void check_user(void* addr, struct intr_frame *  f);
static void check_user_write(void* addr, struct intr_frame *  f);
bool check_validity(struct intr_frame * f);
void check_str(void * str);
void check_buf(void *buffer, unsigned size);
void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt (void);
void exit (int status);
int fork(const char *thread_name,struct intr_frame *f);
int exec (const char *cmd_line);
int wait (int pid);
bool create(const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close(int fd);
void mmap(struct intr_frame *if_);
bool isdir(int fd);
bool chdir (const char *path);
bool mkdir(const char * dir);
bool readdir(int fd, char *file_name);
int inumber(int fd);



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
	

static void check_addr(void* addr){
	/*if minimum needed check addr>(void)0x0*/
    if(is_kernel_vaddr(addr)|| (uint64_t)addr ==0x0 || addr ==NULL||pml4e_walk(thread_current()->pml4,addr,false)==NULL){
		//printf("1\n");
        exit(-1);
		return;
	}
	/*
	void *page_ptr = (void *) pml4_get_page(thread_current()->pml4, addr);
    if (page_ptr == NULL){
		printf("2\n");
        //exit(-1);
		return;
	}*/
} 
#ifdef VM
static void check_user(void* addr,struct intr_frame *f ){
	struct page *p = spt_find_page(&thread_current()->spt, addr);
	if( addr < pg_round_down(f->rsp) && p==NULL )
		exit(-1);
    
} 


static void check_user_write(void* addr,struct intr_frame *f ){
	struct page *p = spt_find_page(&thread_current()->spt, addr);
	if(!p->writable)
		exit(-1);
}
#endif
void check_buffer(void *buffer, unsigned size){
	char *ptr = (char *)buffer;
	for(int i=0;i<size;i++){
		check_addr((void *)ptr);
		ptr++;
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
	if(lock_held_by_current_thread(&file_lock))
		lock_release(&file_lock);
	/*check the fork status*/
	if(t->parent->forked ==1 && status ==-1)
		t->parent->child_status_exit =-1;
	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
}
int fork(const char *thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
}
int exec(const char *cmd_line){
	/*Make child process and get the process descriptor*/
	//lock_acquire(&file_lock);
	int id = process_exec(cmd_line);
	if(id==-1){
		//exit(-1);
		return -1;
	}
	//printf("3\n");
	//lock_release(&file_lock);
	//printf("4\n");
	struct thread * child = get_child_process(id);
	//printf("5\n");
	/*Wait until the child process is loaded*/
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
	if(file==NULL){ 
		//exit(-1);
		return false;
	}
	//check_str(file);
	lock_acquire(&file_lock);
	bool res = filesys_create(file, initial_size);
	lock_release(&file_lock);
	return res;
}
bool remove(const char *file){
	lock_acquire(&file_lock);
	bool res = filesys_remove(file);
	lock_release(&file_lock);
	return res;
}

int open (const char *file){
	/*  Open the file and give the file descriptor
		Ret; the file descriptor
	*/
	if(file==NULL)
		return -1;
	lock_acquire(&file_lock);
	struct file * res;
	res = filesys_open(file);
	if(res==NULL){
		lock_release(&file_lock);
		return -1;
	}
	
	if(!strcmp(file,thread_current()->name))
		file_deny_write(res); 
	int fd = process_add_file(res);
	//printf("open %d\n",fd);
	lock_release(&file_lock);
	return fd;
}
int filesize(int fd){
	/*Find the file with the fd and return the length of the file*/
	//printf("Maybe here?\n");
	//printf("%d\n", fd);
	lock_acquire(&file_lock);
	struct file *f = process_get_file(fd);
	//printf("filesize: fd %d\n", fd);
	//printf("Maybe here?\n");	
	if(f==NULL)
		return -1;
	//printf("Maybe here?\n");
	struct thread *t  = thread_current();
	int size = file_length(t->fd_table[fd]);
	lock_release(&file_lock);
	//printf("Maybe here?\n");
	return size;

}
int read(int fd, void *buffer, unsigned size){
	/*	Read opeeration might occur concurrently, thus we use locks
		find the file with fd and if fd=0 (input)-> save the keyboard input on buffer, and return the saved size
		if not zero -> read the file as much as the given size
	*/
	//printf("HERE-1");
	char* rd_buf = (char *)buffer;
	//printf("HERE-1");
	int count= 0;
	struct file* f;
	lock_acquire(&file_lock);
	//printf("HERE-1");
	if(fd==STDIN_FILENO){
		/*Save input to keyboard->use input_getc (input.h)->one by one*/
		rd_buf[count] = input_getc();
		/*Until the size given + if it is enter, we stop*/
		while(count<size && rd_buf[count]!='\n'){
			count +=1;
			rd_buf[count] = input_getc();
		}
		//printf("HERE-1");
		rd_buf[count] = '\0';
	}else{
		//printf("HERE-1");
		if((f=process_get_file(fd))!=NULL)
			count = file_read(f,buffer,size);
		else
			count =-1;
		//printf("HERE-1");
	}
	lock_release(&file_lock);
	//printf("HERE-1");
	//printf("%d\n",count);
	return count;
}
int write (int fd, const void *buffer, unsigned size){
	/* In order to prevent concurrency, use locks. When we deal with files.
	find the file by fd, and if it is fd=Output signal, we print the buffer
	else, we write it of the buffer size to the file
	*/
	int count = -1;
	struct file* f;
	lock_acquire(&file_lock);
	if(fd==STDOUT_FILENO){
		putbuf((const char *)buffer, size);
		count = size;
	}
	else{
		if((f=process_get_file(fd)) != NULL)
			count = file_write(f, buffer, size);
	}
	lock_release(&file_lock);
	//printf("%d\n",count);
	return count;
}
void seek (int fd, unsigned position){
	/*move the offset as the amount of position/Find file by fd*/
	struct file *f;
	lock_acquire(&file_lock);
	if((f=process_get_file(fd))!=NULL)
		file_seek(f,position);
	lock_release(&file_lock);
}
unsigned tell (int fd){
	/*tell the offset*/
	struct file *f;
	unsigned offset = 0;
	lock_acquire(&file_lock);
	if((f=process_get_file(fd))!=NULL)
		offset = file_tell(f);
	lock_release(&file_lock);
	return offset;
}
void close(int fd){
	/*close the file of the fd and entry initialize*/
	/*
	struct file *f;
	if((f=process_get_file(fd)) !=NULL){
		file_close(f);
		struct thread *t = thread_current();
		t->fd_table[fd] =NULL;
	} */
	process_close_file(fd);
	
}
#ifdef VM
void mmap(struct intr_frame *if_){
	struct file * f; 
	//printf("I WILL KILL YOU\n");
	if((f = process_get_file((int)if_->R.r10)) ==NULL){
		//printf("FUCKING FUCKING FUCKING SHIT\n");
		if_->R.rax = NULL;
	}
	else{
		//struct file * tempo = file_reopen(f);
		//printf("YEAH\n");
		if(!lock_held_by_current_thread(&file_lock))
			lock_acquire(&file_lock);
		//printf("JJ\n");
		if_->R.rax = do_mmap(if_->R.rdi, if_->R.rsi, if_->R.rdx, f, if_->R.r8);
		lock_release(&file_lock);
		//printf("IHERE\n");
	}

}
#endif
bool isdir(int fd){
	struct file * f= process_get_file(fd);
	if(f==NULL)
		exit(-1);
	struct inode * tmp = file_get_inode();
	return inode_is_dir(tmp);
}
bool chdir (const char *path)
{

	char tmp_path[PATH_MAX + 1];
	strlcpy (tmp_path, path, PATH_MAX);
	//FINISH BY /0
	strlcat (tmp_path, "/0", PATH_MAX);
	
	bool success = false;
	char file_name[NAME_MAX + 1];
	struct dir *dir = parse_path (tmp_path, file_name);
	if (dir==NULL)
		return success;
	dir_close (thread_current ()->cur_dir);
	//set new directory by chdir
	thread_current ()->cur_dir = dir; 
	return true;
}

bool mkdir (const char *dir)
{
	return filesys_create_dir (dir);
}
//fd가 invalid하면??????????
bool readdir (int fd, char *file_name)
{
	struct file *f = process_get_file (fd);

	if (f == NULL)
		exit (-1);
	bool success =false;

	struct inode *inode = file_get_inode (f);
	if (inode==NULL || inode_is_dir (inode)==false)
		return success;
	struct dir *dir = dir_open (inode);
	if (dir==NULL)
		return success;



	bool result = true;
	off_t * ofs = (off_t *)f + 1;
	
	int i;
	for (i = 0; i <= *ofs && result; i++){
		result = dir_readdir (dir, file_name);
	}
	if ( (i <= *ofs ) == false)
		(*ofs)++;
	return result;
}

int inumber (int fd)
{
	struct file *f = process_get_file (fd);
	if (f == NULL)
		exit (-1);
	return inode_get_inumber (file_get_inode (f));
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	//thread_current()->rsp = f->rsp;
	check_addr(f->rsp);
	switch(f->R.rax){
		case SYS_HALT:
			//printf("%s\n", "maybe halt?");
			halt();
			//printf("%s\n", "maybe halt?");
			break;
		
		case SYS_EXIT:
			//printf("%s\n", "maybe exit?");
			exit(f->R.rdi);
			break;
		
		case SYS_FORK:
			//printf("%s\n", "maybe fork?");
			check_addr((void *)f->R.rdi);
			int pid = fork((const char *)f->R.rdi,f);
			f->R.rax = pid;
			//printf("%s\n", "maybe fork?");
			
			break;

		case SYS_EXEC:
			//printf("%s\n", "maybe exec?");
			check_addr((void *)f->R.rdi);
			//printf("maybe exec?\n");
			f->R.rax = exec((const char *)f->R.rdi);
			//printf("%s\n", "maybe exec?");
			break;
		
		case SYS_WAIT:
			//printf("%s\n", "maybe wait?");
			f->R.rax = wait(f->R.rdi);
			//printf("%s\n", "maybe wait?");
			break;
		
		case SYS_CREATE:
			//printf("%s\n", "maybe Create?");
			check_addr((void *)f->R.rdi);
			f->R.rax = create((const char *) f->R.rdi, (unsigned) f->R.rsi);
			//printf("%s\n", "maybe Create?");
			break;
		
		case SYS_REMOVE:
			//printf("%s\n", "maybe remove?");
			check_addr((void *)f->R.rdi);
			f->R.rax = remove((const char *) f->R.rdi);
			//printf("%s\n", "maybe remove?");
			break;

		case SYS_OPEN:
			//printf("%s\n", "maybe open?");
			check_addr((void *)f->R.rdi);
			f->R.rax = open((const char*)f->R.rdi);
			//printf("%s\n", "maybe open?");
			break;
		
		case SYS_FILESIZE:
			//printf("%s\n", "maybe fsize?");
			f->R.rax = filesize(f->R.rdi);
			//printf("%s\n", "maybe fsize?");
			break;
		
		case SYS_READ:
			//printf("%s\n", "maybe read?");
			check_addr((void *)f->R.rsi);
#ifdef VM
			//printf("HERE\n");
			check_user((void *)f->R.rsi, f);
			check_user_write((void *)f->R.rsi, f); //why does this happen for reading haun? 
#endif

			f->R.rax = read(f->R.rdi, (void *) f->R.rsi, (unsigned)f->R.rdx);
			//printf("%s\n", "maybe read?");
			break;
		 
		case SYS_WRITE:
			//printf("%s\n", "maybe write?\n");
			check_addr(f->R.rsi);
#ifdef VM
			//printf("HERE\n");
//			check_user((void *)f->R.rsi, f);
//			check_user_write((void *)f->R.rsi, f);
#endif
			//printf("%s\n", "maybe write?\n");
			f->R.rax = write(f->R.rdi, (const void *)f->R.rsi, (unsigned) f->R.rdx);
			//printf("%s\n", "maybe write?\n");
			break;
		
		case SYS_SEEK:
			//printf("%s\n", "maybe seek?\n");
			seek(f->R.rdi, (unsigned)f->R.rsi);
			//printf("%s\n", "maybe seek?\n");
			break;

		case SYS_TELL:
			//printf("%s\n", "maybe tell?\n");
			f->R.rax = tell(f->R.rdi);
			//printf("%s\n", "maybe tell?\n");
			break;
		
		case SYS_CLOSE:
			//printf("%s\n", "maybe close?\n");
			close(f->R.rdi);
			//printf("%s\n", "maybe ok?\n");
			break;
#ifdef VM
		case SYS_MMAP:
			if(check_validity(f)==false) {
				//printf("?\n");
				f->R.rax = NULL;
				break;
			}
			mmap(f);
			//printf("I'vE DONE MMAP\n");
			break;
		case SYS_MUNMAP:
			//printf("THEN MUNMAPhi"\n);
			do_munmap(f->R.rdi);
			break;
			
#endif

		case SYS_ISDIR:
			f->R.rax = isdir((int)f->R.rdi);
			break;
		case SYS_MKDIR:
			f->R.rax = mkdir((const char *)f->R.rdi);
			break;
		case SYS_CHDIR:
			f->R.rax = chdir((const char *)f->R.rdi);
			break;
		case SYS_READDIR:
			check_addr((void *)f->R.rsi);
			f->R.rax = readdir((int)f->R.rdi, (char *) f->R.rsi);
			break;
		case SYS_INUMBER:
			f->R.rax = inumber((int)f->R.rdi);
			break;
		
		default:
			//printf("wrong system call!\n");
			thread_exit();
			break;
	}

}
bool check_validity(struct intr_frame * f){
	//Rdi: address
	if(!is_user_vaddr(f->R.rdi)){
		return false;
	}
	//rsi:length
	if(f->R.rsi==0)
		return false;
	//total zero wrong
	if(f->R.rdi +f->R.rsi ==0)
		return false;
	//r8: ofset
	if(pg_ofs(f->R.r8)!=0)
		return false;
	
	return true;
}
/*
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
}*/
