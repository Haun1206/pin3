#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
static void argument_stack(char * parse[], int count, struct intr_frame *if_);
struct thread * get_child_process(int pid);
void remove_child_process(struct thread *cp);
int process_add_file(struct file *f);
struct file *process_get_file(int fd);
void process_close_file(int fd);
struct lock open_lock;

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;
	lock_init(&open_lock);
	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, strlen(file_name)+1);
    /*
     My addition
     */
    char* save_ptr;
    char *f_name;
    f_name = strtok_r((char*)file_name," ",&save_ptr);
	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (f_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
    //printf("HI");
	supplemental_page_table_init (&thread_current ()->spt);
    //printf("HI");
#endif

	process_init ();
    //printf("%s\n", f_name);
	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	struct thread *t = thread_current();
	t->forked =1;
	tid_t id = thread_create(name, PRI_DEFAULT, __do_fork, if_);
	sema_down(&t->child_fork);
	if(t->child_status_exit ==TID_ERROR)
		id = TID_ERROR;
	return id;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if(!is_user_pte(pte))
		return true;
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER);
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage,parent_page, PGSIZE);
	writable = is_writable(pte);
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		palloc_free_page(newpage);
		//exit(-1);
		return false;
		
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *current = thread_current ();
	struct thread *parent = current->parent;
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = (struct intr_frame *) aux;
	bool succ = true;


	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));


	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;


	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates ->sema
	 * TODO:       the resources of parent.*/

	struct file ** parent_fd_table = parent->fd_table;

	struct file ** child_fd_table = current->fd_table;
	//printf("PARENT: %d\n",parent->next_fd);
	for(int i=2; i<parent->next_fd;i++){
		//printf("HERE1\t");
		/*SHOULD IT BE 2? LITTE CONFUSED*/
		struct file *f = parent_fd_table[i];
		//printf("HERE2\t");
		if(f==NULL)
			break;
		struct file *child_f = file_duplicate(f);
		//printf("HERE3\t");
		if(child_f==NULL){
			//printf("HERE4\t");
			goto error;
		}
		child_fd_table[i] = child_f;
		//printf("HERE5\n");

	}	
	current->next_fd = parent->next_fd;
	//current->next_fd = i+1;


	process_init ();

	/* Finally, switch to the newly created process. */

	sema_up(&parent->child_fork);
	if (succ){
		if_.R.rax = 0;
		do_iret (&if_);
	}
error:
	current->child_status_exit=-1;
	parent->child_status_exit = -1;
	sema_up(&parent->child_fork);
	thread_exit ();

}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
    //printf("HI\n");
	char *file_name = malloc(strlen(f_name)+1);
	memcpy(file_name,f_name,strlen(f_name)+1);
	bool success;
	if(file_name==NULL){
		//thread_exit();
        //printf("HI12\n");
		return -1;
	}
	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();
	/*
    char *tempo;
    char * saveptr;
    tempo = palloc_get_page(0);
    strlcpy(tempo, file_name, strlen(file_name)+1);
    tempo = strtok_r(tempo," ", &saveptr);
	// And then load the binary 
	*/

	success = load (file_name, &_if);
	/*Write the success status to the threads*/
	struct thread * t  = thread_current();
	t->success_load = success;

	/*If succcessful, the do the parent again*/

    /* If load failed, quit. */
    free(file_name);
	if (!success){
		//thread_exit();
        //printf("HI23\n");
		return -1;
	}

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	int res_status;
	//printf("Here\n");
	struct thread* child = get_child_process((int)child_tid);
	//printf("Here\n");
	if(child ==NULL || child->child_status_exit==-1){
		//list_remove(&child->child_elem);
		return -1;
	}
	//printf("Here\n");
		
	/*Wait until the process of child is done */
	sema_down(&child -> wait_sema);
	//printf("Here\n");
	list_remove(&child->child_elem);
	res_status = child->status_exit;
	//printf("Here\n");


	sema_up(&child->exit_sema);
	return res_status;

}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	struct thread *parent = curr->parent;
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	for (curr->next_fd--; curr->next_fd >= 2; curr->next_fd--)
    	process_close_file(curr->fd_table[curr->next_fd]);
		
	//printf("%s\n", "Is this working?");
	palloc_free_page(curr->fd_table);
	/*close the currently running file*/
	curr->process_exit = true;
	//file_close(curr->cur_file);
	/*Check out the child exit staus and parent's forked*/
	if(curr->child_status_exit==-1 && parent->forked ==1){
	//	sema_up(&parent->child_fork);
		list_remove(&curr->child_elem);
	}
	process_cleanup ();


	//printf("%s\n", "clean");
	//sema_up(&curr->load_sema);
	//sema_down(&curr->child_fork);
	
	
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	bool success = false;
	/*
	if(file_name ==NULL){
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}*/
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	
	int i;
    /* Change the file name so that it is the filename that we want*/
    //printf("%d\n", 1);
    char* save_ptr;
    char* token;
    char** arguments = malloc(4*sizeof(char*));

    token = strtok_r((char*)file_name," ", &save_ptr);
    int idx=0;
    int capacity = 4;
    while(token!=NULL){
        arguments[idx] = token;
        idx ++;
        token = strtok_r(NULL, " ", &save_ptr);
        if(idx>=capacity){
            capacity *=2;
            arguments = realloc(arguments, capacity* sizeof(char*));
        }
    }
    int argc = idx;
    
    char * f_name = arguments[0];
    //printf("%d\n", 2);
    
	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL){
		free(arguments);
		//printf("HERE1\n");
		goto done;
	}
	process_activate (thread_current ());

	lock_acquire(&file_lock);
	/* Open executable file. */
	file = filesys_open (f_name);
	lock_release(&file_lock);
	if (file == NULL) {
		printf ("load: %s: open failed\n", f_name);
		free(arguments);
		goto done;
	}
	/*thread's running file will be initialized to the file that will executed
		deny the writing	
		=>protect with lock
	*/
	t->cur_file = file;
	file_deny_write(file);
	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		free(arguments);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file)){
			//printf("HERE5\n");
			goto done;
		}
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr){
			//printf("HERE4\n");
			goto done;
		}
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
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
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable)){
						//printf("HERE3\n");
						goto done;
					}
				}
				else{
					//printf("HERE2\n");
					goto done;
				}
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_)){
		//printf("sdfsdf1\n");
		goto done;
	}

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
    //printf("%d\n", 3);

    argument_stack(arguments,argc,if_);

	success = true;
	free(arguments);
    //printf("%d\n",4);
done:
	/* We arrive here whether the load is successful or not. */
    //printf("%d\n",4);
	file_close (file);
	//free(arguments);
	printf("RESULT: %d\n",success);
	return success;
}


static void argument_stack(char * parse[], int count, struct intr_frame *if_){
    uintptr_t ** rsp = &if_->rsp;
    int ** arguments_address;
    arguments_address = malloc(count*sizeof(char*));
    int len=0;
    for(int i=0;i<count;i++){
        len = 0;
        len += strlen(parse[count-i-1]);
        len++;
        *rsp = (uint64_t)(*rsp)-len;
        memcpy(*rsp, parse[count-i-1],len);
        arguments_address[i] = *rsp;
    }
    //printf("%s\n", "YES:");
    while((uint64_t)(*rsp)%8!=0){
        *rsp = (uint64_t)(*rsp)-1;
    }
    
    *rsp -= 1;
    **rsp = 0;
   // printf("%s\n", "YES:");
    /* setting argv[i] of having the addresses */
    for (int i = 0; i <count ; i++) {
        *rsp -= 1;
        memcpy(*rsp,&arguments_address[i], sizeof(char*));
    }

    /* setting argv as rsi*/
    if_->R.rsi = (uint64_t)(*rsp);
    
    /*setting argc has rdi */
    if_->R.rdi = count;
    //printf("%p\n", if_->R.rsi);
    // setting ret addr
    *rsp -= 1;
    *(int*)*rsp = 0;
    int size = (uint64_t)(USER_STACK) - (uint64_t)(*rsp);
    //hex_dump((uintptr_t)(*rsp), *rsp, size, true);
    
    
}
/*
	Search the child list based on the pid and return the process descriptor 
*/
struct thread * get_child_process(int pid){
	struct thread *t = thread_current();
	struct list_elem *e = list_begin(&t->child);
	while(e!=list_end(&t->child)){
		struct thread *temp = list_entry(e,struct thread, child_elem);
		if(pid == temp->tid) 
			return temp;
		e = list_next(e);
	}
	return NULL;

}

/* remove the child process and delete process descriptor memory*/

void remove_child_process(struct thread *cp){
	if(cp==NULL) 
		return;
	if(cp->process_exit ==true)
		list_remove(&(cp->child_elem));
	//palloc_free_page(cp);
}

int process_add_file(struct file *f){
	/*Add the file to the file descriptor table
	Make the file descriptor's maximum value incremented */
	struct thread* t = thread_current();
	int next = t->next_fd;
	if( t->fd_table==NULL){
		file_close(f);
		return -1;
	}
	
	t->fd_table[next] = f;
	t->next_fd = t->next_fd +1;
	return next;
}

struct file* process_get_file(int fd){
	/*return the file that has the fd, but if the fd is invalid, we might not get the file*/
	struct thread* t = thread_current();
	if(fd>= t->next_fd||fd<=1)
		return NULL;
	return t->fd_table[fd];
}

/*close the file for the fd
Also initialize the entry at that file descriptor*/
void process_close_file(int fd){
	//struct file * rm_file = palloc_get_page(PAL_USER);
	//rm_file = process_get_file(fd);
	struct file *rm_file = process_get_file(fd);
	struct thread* t = thread_current();
	if(rm_file==NULL|| fd<2 || t->next_fd <= fd )
		return;
	
	//printf("HI\n");
	//printf("%d\n", fd);
	file_close(rm_file);
	//printf("HI\n");
	/*Initialization*/

	t->fd_table[fd] = NULL;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
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

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
    
    struct aux_load * aux_t = (struct aux_load *)aux;
    
    //In aux it has file, ofs, read_bytes, zero_bytes, writable
    //Should modify this part
    /* Get a page of memory. */
    if(page->frame==NULL)
        return false;
    else{
        uint8_t * kva = page->frame->kva;
        if (file_read_at(aux_t->file, kva, aux_t->read_bytes, aux_t->ofs) != (int) aux_t->read_bytes) {
            printf("SOMETHING IS WRONG\n");
            return false;
        }
        /* Load this page. */

        memset (kva + aux_t->read_bytes, 0, aux_t->zero_bytes);
    }


  
    return true;
    
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);
	//printf("IAM HERE\n");
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
        struct aux_load * aux = malloc(sizeof(struct aux_load));
		//printf("1?\n");
        aux->file = file;
        aux->ofs = ofs;
        //aux->upage = upage;
        aux->read_bytes = read_bytes;
        aux-> zero_bytes = zero_bytes;
        aux->writable = writable;
		//printf("2?\n");
        
        
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux)){
			printf("THEN IS IT HERE?\n");
			return false;
		}
		//printf("3?\n");

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs +=PGSIZE;
		//printf("4?\n");
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
    if(vm_alloc_page(VM_MARKER_0 | VM_ANON, stack_bottom, true)){
		if(vm_claim_page(stack_bottom)){
		
        	if_->rsp = stack_bottom+PGSIZE;
        	success = true;
   		}
	}
	return success;
}
#endif /* VM */
