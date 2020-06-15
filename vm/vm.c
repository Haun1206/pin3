/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"

#include "vm/vm.h"
#include "vm/inspect.h"
#include <hash.h>
#include "threads/mmu.h"
#include "threads/synch.h"
#include "vm/uninit.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "vm/anon.h"
#include "vm/vm.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <list.h>
#include <stdlib.h>

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&victim_list);
	lock_init(&evict_lock);
	victim_c = list_head(&victim_list);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}



/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
static uint64_t vm_hash_func(const struct hash_elem *e, void * aux UNUSED);
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b);
static void spt_destroy_func(struct hash_elem*e,void *aux);


/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
        struct page * p = malloc(sizeof(struct page));

        switch(VM_TYPE(type)){
            case VM_ANON:
                uninit_new(p,upage,init,type,aux,&anon_initializer);
				p -> mapping = -1;
                break;
            case VM_FILE:
				uninit_new(p, upage, init, type, aux, &file_map_initializer);
				p->mapping = ((struct aux_map * )aux)->mapping;
                break;
            case VM_PAGE_CACHE:
                break;
            default:
                break;
        }
		p->writable = writable;


		/* TODO: Insert the page into the spt. */
		//printf("1\n");
        if(spt_insert_page(spt,p)){
			return true;
		}
		else
			goto err;
		
		

		//printf("1\n");
	}
err:

	//printf("?\n");
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page p;
    p.va = pg_round_down(va);
    struct hash_elem * elem= hash_find(&spt->hash_table, &p.h_elem);

    if (elem==NULL)
        return NULL;
    else
        return hash_entry(elem,struct page, h_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	if (spt_find_page(spt,page->va)!=NULL)
		return false;
	/* TODO: Fill this function. */
	bool succ =false;
	/*
	if(!lock_held_by_current_thread(&spt_lock))
		lock_acquire(&spt_lock); */
    if(hash_insert(&spt->hash_table, &page->h_elem) ==NULL)
        succ=true;
	/*
	if(lock_held_by_current_thread(&spt_lock))
		lock_release(&spt_lock); */
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	
	if (hash_delete(&spt->hash_table, &page->h_elem))
	{
		pml4_clear_page (thread_current()->pml4, page->va);
		vm_dealloc_page (page);
		return true;	
	}
	//vm_dealloc_page(page);

	//free(page->frame);
	return false;
}


/* Get the struct frame, that will be evicted. */
static struct frame * vm_get_victim (void) {
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */
	struct frame *tmp;
	void * addr;
	victim_c = list_begin(&victim_list);
	while(victim_c!=NULL){
		tmp  = list_entry(victim_c, struct frame, victim);
		addr = tmp -> page ->va;
		//already accessed
		if (!pml4_is_accessed(thread_current()->pml4, addr)) {
			victim = tmp;
			return victim;
		}
		else
			pml4_set_accessed(thread_current()->pml4, addr, false);
		
		victim_c = list_next(&victim_c);
	
	}
	if (victim == NULL){
		struct list_elem * victim_c2 = list_begin(&victim_list);
		victim = list_entry(victim_c2,struct frame, victim);
	}

	//list_remove(&victim->victim);
	return victim;

}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
    frame = malloc(sizeof(struct frame));
	ASSERT (frame != NULL);
    frame->kva = palloc_get_page(PAL_USER);
    if(frame->kva==NULL){
        free(frame);
		lock_acquire(&evict_lock);
		frame = vm_evict_frame();
		lock_release(&evict_lock);
	}
	frame->page= NULL;
	list_push_back(&victim_list, &frame->victim);
	ASSERT(frame->page ==NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	void * bottom=pg_round_down(addr);
	while(vm_alloc_page(VM_MARKER_0|VM_ANON,bottom, true)){
		
		vm_claim_page(bottom);
		bottom +=PGSIZE;
	}

}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if(addr==NULL)
		exit(-1);
	if (write && !not_present)
		exit(-1);
	//printf("not_presetn: %d write: %d user: %d addr: %x\n", not_present, write, user, addr);



	uint64_t u_rsp=NULL;
	if(user)
		u_rsp = f->rsp;
	else
		u_rsp = thread_current()->rsp;
	//thread_current()->rsp = u_rsp;

	page = spt_find_page(spt,addr);
	
	if(page!=NULL){
		if(!not_present&&is_user_vaddr(addr))
			exit(-1);
		if((!(page->writable)) && write){
			//printf("HERE\n");
			exit(-1);
		}
		//printf("HERE\n"); <-왜 이리 쳐오고 jiral?

		if(VM_TYPE(page->operations->type) == VM_ANON || VM_TYPE(page->operations->type) == VM_FILE) {
			struct frame *frame = vm_evict_frame();
			page->frame = frame;
			return swap_in(page, frame->kva);
		}
		//printf("INIT\n");
		//int i = vm_do_claim_page(page);
		return vm_do_claim_page (page);
	}
	else{
		//printf("HEREdfsfdsf\n");
		//If bigger thant the current rsp &1MB restriction
		
		if(((uint64_t)addr > u_rsp - PGSIZE )&&(pg_no(USER_STACK) - pg_no(addr)) <= 250){
		//	printf("HERE2\n");
			vm_stack_growth(addr);
			return true;
		}
		//free(page);
		return false;
	}
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
    page = spt_find_page(&thread_current()->spt,va);
	if(page==NULL)
		return false;
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	if(page==NULL)
		return false;
	struct frame *frame = vm_get_frame ();
    
	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	
    pml4_set_page(thread_current()->pml4, page->va, frame->kva, true);
	return swap_in (page, frame->kva);
}

static uint64_t vm_hash_func(const struct hash_elem *e, void * aux ){
    struct page * temp = hash_entry(e, struct page, h_elem);
    uint64_t res = hash_bytes(&temp->va, sizeof(temp->va));
    return res;
    //Should I omit &?
}
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b){
    const struct page * fst = hash_entry(a,struct page, h_elem);
    const struct page * snd = hash_entry(b,struct page, h_elem);
    return fst->va < snd->va;
}
/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt ) {
    hash_init(&spt->hash_table, vm_hash_func, vm_less_func, NULL);
	lock_init(&spt_lock);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED) {
	//from src to dst
	
	struct hash_iterator i;
	lock_acquire(&spt_lock);
	hash_first(&i,&src->hash_table);
	struct aux_load *aux_t;
	bool res =false;
	while(hash_next(&i)){
		struct page *p = hash_entry(hash_cur(&i),struct page, h_elem);
		switch (p->operations->type){
			case VM_UNINIT:
				//we need to copy the members
				aux_t = malloc(sizeof(struct aux_load));
				memcpy(aux_t,p->uninit.aux, sizeof(struct aux_load));
				res = vm_alloc_page_with_initializer(p->uninit.type,p->va, p->writable, p->uninit.init, aux_t);
				break;
			default:
				res= vm_alloc_page(p->operations->type, p->va, p->writable);
				if(res==1){
					struct page * d =spt_find_page(&thread_current()->spt, p->va);
					if(vm_claim_page(p->va)==0)
						printf("SOMETHING IS WRONG\n");
					memcpy(d->frame->kva, p->frame->kva, PGSIZE);
				}
				break;



		}
		
	}
	lock_release(&spt_lock);
	return res;
}

static void spt_destroy_func(struct hash_elem*e,void *aux){
	struct page *p = hash_entry(e,struct page, h_elem);
	
	destroy(p);
	free(p);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	if(hash_empty(&spt->hash_table))
		return;
	hash_clear(&spt->hash_table,spt_destroy_func);
}
