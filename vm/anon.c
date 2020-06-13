/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "bitmap.h"
#include "threads/mmu.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1,1);
	disk_size(swap_disk)/SECTOR_PG;
	swap_table = bitmap_create(disk_size(swap_disk)/SECTOR_PG);

}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {

	struct anon_page *anon_page = &page->anon;
	size_t number = anon_page -> number;

	for (int i = 0; i < SECTOR_PG; i++){
		disk_read(swap_disk, number * SECTOR_PG+ i, kva + i * 512);
	}
	pml4_set_page(thread_current()->pml4, page->va, page->frame->kva, page->writable);
	page->frame->kva = kva;
	page->frame->page = page;
	list_push_back(&victim_list, &page->frame->victim);
	bitmap_set(swap_table, number, false);
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	size_t number = bitmap_scan (swap_table, 0, 1, false);
	anon_page->number = number;
	for (int i = 0; i < SECTOR_PG; i++)
		disk_write(swap_disk, number * SECTOR_PG + i, page->frame->kva + 512*i);
	pml4_clear_page(thread_current()->pml4, page->va);
	
	bitmap_set(swap_table, number, true);
	page->frame = NULL;

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	free(page->frame);
}
