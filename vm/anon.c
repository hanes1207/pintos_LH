/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/synch.h"

struct lock swap_disk_lock;
struct list free_swap_disk_blocks;

#define SAFE_LOCK_SWAPDISK(code) if(!lock_held_by_current_thread(&swap_disk_lock)){lock_acquire(&swap_disk_lock);} code if(lock_held_by_current_thread(&swap_disk_lock)){lock_release(&swap_disk_lock);}

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

void 
swap_disk_block_save(struct swap_disk_block* sdblk, const void* va){
	for(int i=0; i<SWAP_DISK_BLOCK_SECTORS; ++i){
		disk_write(swap_disk, sdblk->sectors[i], (((uint8_t*)va) + DISK_SECTOR_SIZE * i));
	}
}
void
swap_disk_block_load(struct swap_disk_block* sdblk, void *va){
	for(int i=0; i<SWAP_DISK_BLOCK_SECTORS; ++i){
		disk_read(swap_disk, sdblk->sectors[i], (((uint8_t*)va) + DISK_SECTOR_SIZE * i));
	}
}

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	//swap_disk = NULL;
	lock_init(&swap_disk_lock);
	list_init(&free_swap_disk_blocks);

	//Disk retrieval
	swap_disk = disk_get(1,1);
	uint32_t swap_disk_sector_cnt = disk_size(swap_disk);
	//printf("Swap disk size = %"PRDSNu"\n", disk_size(swap_disk));

	//Free swap disk block 
	for(int i=0; i < swap_disk_sector_cnt / SWAP_DISK_BLOCK_SECTORS; ++i){
		struct swap_disk_block* sdblk = malloc(sizeof(struct swap_disk_block));
		for(int j=0; j<SWAP_DISK_BLOCK_SECTORS; ++j){
			sdblk->sectors[j] = SWAP_DISK_BLOCK_SECTORS * i + j;
		}
		list_push_back(&free_swap_disk_blocks, &sdblk->elem);
	}
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	struct swap_disk_block* sdblk = anon_page->sdblk;
	//printf("anon_swap_in(%p, %p) : va=%p, sdblk=%p\n", page, kva, page->va, sdblk);
	if(sdblk == NULL){
		PANIC("No swap disk block but swap-in required.");
	}
	SAFE_LOCK_SWAPDISK(
		swap_disk_block_load(anon_page->sdblk, kva);
		anon_page->sdblk = NULL;
		list_push_back(&free_swap_disk_blocks, &sdblk->elem);
	)
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	//printf("anon_swap_out(%p) : va=%p\n", page, page->va);
	SAFE_LOCK_SWAPDISK(
		if(!list_empty(&free_swap_disk_blocks)){
			//There is a free swap disk block.
			struct list_elem* el = list_pop_front(&free_swap_disk_blocks);
			struct swap_disk_block* sdblk = list_entry(el, struct swap_disk_block, elem);
			//printf("\tsdblk(%p)\n", sdblk);
			anon_page->sdblk = sdblk;
			swap_disk_block_save(sdblk, page->va);
		} else {
			//I'm not god.
			PANIC("Insufficient swap disk block");
			PANIC("");
			NOT_REACHED();
		}
	)
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	//Free swap disk sectors
}
