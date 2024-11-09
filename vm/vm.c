/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"
#include "threads/mmu.h"

#include <stdio.h>

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
struct list frame_list;
static void page_print(struct hash_elem *elem, void* aux UNUSED);
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
	list_init(&frame_list);
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

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	
	/* Check whether the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		/* TODO: Insert the page into the spt. */

        struct page *page = (struct page *)malloc(sizeof(struct page));
		//printf("type=%d, is_anon=%d\n", type, (type == VM_ANON));
        // vm_initializer: page fault가 최초로 발생했을 때 실행됨
        //  ex) lazy_load_segment (struct page *page, void *aux)
        //  load segment from file
        // (*page_initializer) (struct page *, enum vm_type, void *kva): Initiate the struct page and maps the pa to the va
        //  ex) 
		
        uninit_new(page, upage, init, type, aux, (type == VM_ANON) ? anon_initializer : file_backed_initializer);
        page->writable = writable;

		spt_insert_page(spt, page);	//이거 안해주면 나중에 관리 불가
        return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	//printf("spt_find_page(spt, %p)\n", va);
	struct page *page = NULL;
	/* TODO: Fill this function. */
	struct page key;
	key.va = pg_round_down(va);
	

    struct hash_elem* pelem = hash_find(&spt->pages, &key.elem);
	if(pelem == NULL){
		//puts("Not Found");
		return NULL;
	}
	struct page* target_page = hash_entry(pelem, struct page, elem);
	//printf("Found page info : Type=%d, VA=%p\n",target_page->operations->type, target_page->va);
	return hash_entry(pelem, struct page, elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	int succ = false;
	/* TODO: Fill this function. */
	//printf("#### spt_insert_page()\n");
	if(spt_find_page(spt, page->va) == NULL){
		hash_insert(&spt->pages, &page->elem);
		//printf("#### spt_insert_page() succeed\n");
		return true;
	} else {
		//printf("#### spt_insert_page() failed\n");
		return false;
	}
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
	struct frame *frame = (struct frame*)malloc(sizeof(struct frame));
	/* TODO: Fill this function. */
	enum palloc_flags flag = PAL_USER;
	void* got_frame = palloc_get_page(flag);
	if(got_frame == NULL){
		PANIC("todo");
	}
	frame->kva = got_frame;
	frame->page = NULL;
	list_push_back(&frame_list, &frame->elem);

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
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
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	void* pgaddr = pg_round_down(addr);
	page = spt_find_page(spt, pgaddr);
	if(page == NULL)
		return false;
	/*if(addr <= USER_STACK && addr >= USER_STACK - 1000000){
		printf("Recoverable Stack Pagefault : addr=%p, rsp(if)=%p\n", addr, f->rsp);
	}*/
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
// stack growing 같은거 할 때 필요함
bool
vm_claim_page (void *va) {
	struct page* page = spt_find_page(&thread_current()->spt, va);
	if(page == NULL){
		// Stack growing 시, hash table에 미리 없을 것이므로 이 경우에는 새로운 page가 만들어져야 한다.
		page = malloc(sizeof(struct page));
		uninit_new(page, va, NULL, VM_ANON, NULL, anon_initializer);
		page->writable = true;
		spt_insert_page(&thread_current()->spt, page);
	}
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
	struct thread* t = thread_current();

	void* va = page->va;
	bool succ = (
		pml4_get_page (t->pml4, va) == NULL &
		pml4_set_page(thread_current()->pml4, va, frame->kva, page->writable)
	);	//TODO : rw may not be always true(think about code section)
	if(!succ){
		hash_apply(&t->spt.pages, page_print);
	}
	ASSERT(succ == true);
	return swap_in (page, frame->kva);
}

// aux에 process 정보가 있어야 할거고
uint64_t page_hash_func(const struct hash_elem*e, void *aux UNUSED){
	uint64_t target_val = hash_entry(e, struct page, elem)->va;
	target_val >>= (PGBITS);
	target_val %= 17;
	return target_val;
}
bool page_hash_less_func(const struct hash_elem* a, const struct hash_elem* b, void*aux UNUSED){
	return ((uint64_t)(hash_entry(a, struct page, elem)->va)) 
		< ((uint64_t)(hash_entry(b, struct page, elem)->va));
}
void page_print(struct hash_elem *elem, void* aux UNUSED){
	struct page* page = hash_entry(elem, struct page, elem);
	printf(
		"page : type=%d, va=%p, frame=%p, kva=%p\n", 
		page->operations->type, 
		page->va, 
		page->frame, 
		(page->frame == NULL ? NULL : page->frame->kva)
	);
}
/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	ASSERT(spt != NULL);
	//본 함수는 __do_fork 및 initd에서 실행됨으로서 모든 프로세스에서 실행된다.
	//process_exec에서는 
	//process_cleanup을 실행, supplemental_page_table_kill을 실행하고, 
	//이후 load에서 pml4_create를 한다.
	//따라서 load에서도 supplemental_page_table_init()을 수행해주는 것이 옳다.
	
	
    // 1. initd를 위한 spt init이 있고
    // 2. do_fork했을 때 spt 카피 떠서 새로 만들어야 하고
    // 3. exec할 때 lazy loading 구현해야지
    hash_init(&spt->pages, page_hash_func, page_hash_less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	ASSERT(dst != NULL && src != NULL);
	struct hash_iterator I;
	hash_first(&I, &src->pages);
	while(hash_next(&I)){
		struct page* p = hash_entry(hash_cur(&I), struct page, elem);
		//TODO : Copy page
		//hash_insert(&dst->pages, /**/);
	}
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
