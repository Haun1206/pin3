/* file.c: Implementation of memory mapped file object (mmaped object). */

#include "vm/vm.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"

static bool file_map_swap_in (struct page *page, void *kva);
static bool file_map_swap_out (struct page *page);
static void file_map_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_map_swap_in,
	.swap_out = file_map_swap_out,
	.destroy = file_map_destroy,
	.type = VM_FILE,
};
int counter;
/* The initializer of file vm */
void
vm_file_init (void) {
	counter =0;
}

/* Initialize the file mapped page */
bool
file_map_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_map_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_map_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file mapped page. PAGE will be freed by the caller. */
static void
file_map_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

int check_addr(void * addr, size_t length){
	void * i = addr;
	struct supplemental_page_table * spt = &thread_current()->spt;
	//CHECK ALL THE ADDRESSES 
	while(i<=pg_round_down(addr+length)){
		if(!is_user_vaddr(i))
			return 0;
		if(spt_find_page(spt,i)!=NULL)
			return 0;
		i+= PGSIZE;
	}
	return 1;
}
/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
	
	if(check_addr(addr,length)==0)
		return;
	

	uint32_t read_bytes = (uint32_t)length;
	counter ++;
	
	
	
	
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
