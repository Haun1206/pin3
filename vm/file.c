/* file.c: Implementation of memory mapped file object (mmaped object). */

#include "vm/vm.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

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
    //If the file was written we might need to write it back again
    struct thread *t  = thread_current();
    if(pml4_is_dirty(t->pml4, page->va)){
        if(page->frame != NULL)
            file_write_at(page->file.file, page->frame->kva, page->file.read_bytes, page->file.ofs);
        

    }
    //If the page has the physical memeory ->free
    if(page->frame !=NULL){
        palloc_free_page(page->frame->kva);
        free(page->frame);
    }

}

int check_addr(void * addr, size_t length){
    void * i = addr;
    struct supplemental_page_table * spt = &thread_current()->spt;
    //CHECK ALL THE ADDRESSES 
    while(i<=pg_round_down(addr+length)){
        if(!is_user_vaddr(i))
            return 0;
        //overlap
        if(spt_find_page(spt,i)!=NULL)
            return 0;
        i+= PGSIZE;
    }
    return 1;
}
/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
    
    if(file_length(file)==0){
        return NULL;
    }
    if(addr ==0x0)
        return NULL;
    if(length<=0){
        return NULL;
    }
    if(pg_ofs(addr)!=0)
        return NULL;
    if(check_addr(addr,length)==0)
        return NULL;
    //printf("HIdfsdfds\n");
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
    //printf("UNTIL HER\n");
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
    //printf("UNTIL HER\n");

    return orig_address;
    
    
}
//LAZY MAPPING
//AUX 프리 잊지 않기
bool lazy_map(struct page *p, void * aux){
    struct aux_map * aux_t = (struct aux_map *)aux;

            /*
            struct file_page {
            struct file *file;
            off_t ofs;
            uint32_t read_bytes;
            uint32_t zero_bytes;
        };


        struct aux_map {
            struct file *file;
            off_t ofs;
            uint32_t read_bytes;
            uint32_t zero_bytes;
            int mapping;
        };
*/
    
    //In aux it has file, ofs, read_bytes, zero_bytes, writable
    //Should modify this part
    /* Get a page of memory. */
    if(p->frame==NULL)
        return false;
    else{
        struct file *reopen = file_reopen(aux_t->file);
        uint8_t * kva = p->frame->kva;
        int read_bytes = file_read_at(reopen, kva, aux_t->read_bytes, aux_t->ofs);
        int zero_bytes = PGSIZE - read_bytes;

        memset (kva + read_bytes, 0, zero_bytes);

        //SEt the struct file_page the components
        p->file.file = aux_t->file;
        p->file.ofs = aux_t->ofs;
        p->file.read_bytes = read_bytes;
        p->file.zero_bytes = zero_bytes;
        
        free(aux);
        return true;
    }
    
}


/* Do the munmap 
All pages written to the proces are written back to file/ not written not written back
Pages removed from process's list of vp ->delete hash 


*/
void do_punmap (struct hash_elem *e, void *aux){
	
	int check_mapping  = (int)aux;
	struct page *page = hash_entry(e, struct page, h_elem);
	struct thread* t = thread_current();
	if(page->mapping == check_mapping) {
		if (VM_TYPE(page->operations->type) == VM_FILE && pml4_is_dirty(thread_current()->pml4, page->va))
		{
			if (page->frame)
			{
				file_write_at(page->file.file, page->frame->kva, page->file.read_bytes, page->file.ofs);
				
				//find the file's location in fd_table
				//And backup
				for(int i = 2; i < t->next_fd; i++){
					if(t->fd_table[i] == page->file.file)
						t->fd_table[i] = file_reopen(page->file.file);
				}
			}
		}
		spt_remove_page(&thread_current()->spt, page);
	}
}
void
do_munmap (void *addr) {
    //printf("MUNMAP\n");
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = spt_find_page(spt, addr);
	struct file *file = page->file.file;

	spt->hash_table.aux = page->mapping;
    lock_acquire(&spt_lock);
	hash_apply (&spt->hash_table, do_punmap);
    lock_release(&spt_lock);
	file_close(file);

}
