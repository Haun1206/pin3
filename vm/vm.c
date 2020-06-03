/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <hash.h>
#include "threads/mmu.h"
#include "vm/uninit.h"
#include "threads/vaddr.h"
#include "threads/thread.h"

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

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`.
 * DO NOT MODIFY THIS FUNCTION. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
    struct page * npage = malloc(sizeof(struct page));
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
        struct page * p = palloc_get_page(PAL_USER);
        switch(VM_TYPE(type)){
            case VM_ANON:
                uninit_new(npage,upage,init,type,aux,&anon_initializer);
                break;
            case VM_FILE:
                break;
            case VM_PAGE_CACHE:
                break;
            default:
                break;
        }
        
		/* TODO: Insert the page into the spt. */
		//printf("1\n");
        if(spt_insert_page(spt,p)){
			return true;
		}
		else{
			palloc_free_page(p);
			goto err;
		}
		//printf("1\n");
	}
err:

	//printf("?\n");
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
    page = malloc(sizeof(struct page));
    page -> va = va;
    struct hash_elem * elem= hash_find(spt->hash_table, &page->h_elem);
    free(page);
    if (elem==NULL)
        return NULL;
    else
        return hash_entry(elem,struct page, h_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	printf("HI\n");
	/* TODO: Fill this function. */
    if(hash_insert(spt->hash_table, &page->h_elem) ==NULL)
        succ = true;
	printf("HI\n");
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
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
    if(frame->kva ==NULL)
        PANIC("todo");
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
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

	return vm_do_claim_page (page);
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
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
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
    spt->hash_table = malloc(sizeof(struct hash));
    hash_init(spt->hash_table, vm_hash_func, vm_less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
