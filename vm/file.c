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
	
	if(length==0)
		return NULL;
	if(!addr)
		return NULL;
	if(check_addr(addr,length)==0)
		return NULL;
	void * orig_address = addr;
	//Need to initialize the read_bytes and the zero_bytes
	//
	//printf("%x\n",read_bytes);
	uint32_t read_bytes = (uint32_t)length;
	uint32_t remainder = PGSIZE- read_bytes%PGSIZE;
	uint32_t  zero_bytes = 0;
	if(remainder!=0){
		zero_bytes = remainder;
	}
	//ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
	//printf("%x\n",zero_bytes);
	counter ++;
	
	while (read_bytes > 0 || zero_bytes > 0) {

		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct aux_map * aux = malloc(sizeof(struct aux_map));
		//printf("1?\n");
        aux->file = file;
        aux->ofs = offset;
        aux->read_bytes = read_bytes;
        aux-> zero_bytes = zero_bytes;
        aux-> mapping = counter;
		//printf("2?\n");
        
        
		if (!vm_alloc_page_with_initializer (VM_FILE, addr, writable, lazy_map, aux)){
			//printf("THEN IS IT HERE?\n");
			return NULL;
		}
		//printf("3?\n");

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset +=PGSIZE;
		//printf("4?\n");
	}

	return orig_address;
	
	
}

bool lazy_map(struct page *p, void * aux){
	struct aux_map * aux_t = (struct aux_map *)aux;
    
    //In aux it has file, ofs, read_bytes, zero_bytes, writable
    //Should modify this part
    /* Get a page of memory. */
    if(p->frame==NULL)
        return false;
    else{
        struct file *reopen = file_reopen(aux_t->file);
        uint8_t * kva = page->frame->kva;
        if (file_read_at(reopen, kva, aux_t->read_bytes, aux_t->ofs) != (int) aux_t->read_bytes) {
           // printf("SOMETHING IS WRONG\n");
            return false;
        }
        /* Load this page. */

        memset (kva + aux_t->read_bytes, 0, aux_t->zero_bytes);
    }
 
 
  
    return true;
	
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
