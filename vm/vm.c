/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"
#include "threads/mmu.h"

#include <string.h>
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
	if(page->frame != NULL){
		//연결된 프레임 삭제
		list_remove(&page->frame->elem);
		palloc_free_page(page->frame->kva);
		free(page->frame);
	}
	hash_delete(&spt->pages, &page->elem);
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
		free(frame);
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
vm_stack_growth (void *addr) {
	ASSERT(vm_claim_page(pg_round_down(addr)));
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {

}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;

	//printf("try_handle : %p : user=%d, write=%d, not_present=%d\n",addr, user, write, not_present);
	//hash_apply(&thread_current()->spt.pages, page_print);
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if(((uintptr_t)addr) >= KERN_BASE)
		return false;
	
	if(not_present){
		void* pgaddr = pg_round_down(addr);
		page = spt_find_page(spt, pgaddr);
		if(page == NULL){
			//SPT가 없지만, stack growth라면 살리도록 한다.
			if(addr <= USER_STACK && addr >= USER_STACK - 1048576){
				//printf("Recoverable Stack Pagefault : addr=%p, rsp(if)=%p\n", addr, thread_current()->rsp);
				//Is rsp value reliable?

				// 배열 선언의 경우, rsp를 먼저 빼고 시작함으로 rsp와 addr이 같다.
				// 그러나 (-4096)rsp와 같은 비정상적 메모리 접근 시도의 경우, rsp를 먼저 늘리지 않으므로 rsp가 addr보다 크다
				if(thread_current()->rsp < addr){
					vm_stack_growth(addr);
					return true;
				}
				if(thread_current()->rsp - ((uintptr_t)addr) < 16){
					//PUSH CASE
					//Stack growth(1 frame)
					vm_stack_growth(addr);
					thread_current()->rsp = addr;
					if(user)
						f->rsp = addr;
					return true;
				}
			}
			//DEFAULT ACTION IS DIE
			//puts("BAD_STACK_GROWTH_ERROR");
			thread_exit();	//죽어라 히히
			return false;
		}
		return vm_do_claim_page (page);
	} else if(write){
		//puts("WRITE PERMISSION DENIED");
		return false;
	}
	return false;
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

	//printf("vm_do_claim_page() : page->va=%p, page->writable=%p\n", page->va, page->writable);
	void* va = page->va;
	const bool is_prev_addr_not_exist = (pml4_get_page (t->pml4, va) == NULL);
	if(!is_prev_addr_not_exist){
		return false;
	}
	//printf("do_claim_page : %p : page->writable = %d\n", page->va, page->writable);
	bool succ = (is_prev_addr_not_exist & pml4_set_page(thread_current()->pml4, va, frame->kva, page->writable));

	//DEBUG_LOGGER
	if(!succ){
		printf("pml4_get_page(%p) = %p\n", va, vtop(pml4_get_page (t->pml4, va)));
		hash_apply(&t->spt.pages, page_print);
		return false;
	}

	//ASSERT(succ == true);
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
		"page : type=%d, va=%p, frame=%p, kva=%p, writable=%d\n", 
		page->operations->type, 
		page->va, 
		page->frame, 
		(page->frame == NULL ? NULL : page->frame->kva),
		page->writable
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
		struct supplemental_page_table *src) {  // dst는 &current->spt이고, src는 &parent->spt이다
	ASSERT(dst != NULL && src != NULL);
	//1. Init dst's hash table
	hash_init(&dst->pages, page_hash_func, page_hash_less_func, NULL);

	//2. Copy hash table entries
	struct hash_iterator I;
	hash_first(&I, &src->pages);
	while(hash_next(&I)){
		struct page *p = hash_entry(hash_cur(&I), struct page, elem);
		//TODO : Copy page
		//hash_insert(&dst->pages, /**/);
        struct page *copied = (struct page *)malloc(sizeof(struct page));
		spt_entry_copy(copied, p);
        hash_insert(&dst->pages, &copied->elem);
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill_entry_action(struct hash_elem *element, void *aux){
	struct page* page = hash_entry(element, struct page, elem);
	if(page->frame != NULL){
		//연결된 프레임 삭제
		list_remove(&page->frame->elem);
		//palloc_free_page(page->frame->kva);
		free(page->frame);
	}
	vm_dealloc_page (page);
	return;
}

//SPT hash table 자체를 삭제하는 것은 process exit 직전에 한다.
//왜냐하면 process exec을 했을 때 lazy loading을 하기 위해서는 SPT hash table '자체'는 살아있어야 하기 때문이다.
//process_exec에서는 process_cleanup()을 통해 SPT_kill을 하지만, 이후 SPT를 다시 init하지 않고 바로 사용한다.
//즉, SPT_kill에서 hash table자체를 완전히 없앤다면, 오류가 발생할 수밖에 없다.
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->pages, supplemental_page_table_kill_entry_action);
}

bool page_cont_copy (struct page* page, void* aux) {
	//Exceptionally, for this aux, not free.
	//Because page_cont_copy will be executed immediately when VM_UNINIT page created.
	//so, there is no such case these page will be copied before this function
	//(which can cause copy error)
	memcpy(page->frame->kva, ((struct page*)aux)->frame->kva, PGSIZE);
	return true;
}

void
spt_entry_copy (struct page *dst, struct page *src) {
	// Treat different cases
	struct vm_initializer_aux* uninit_case_copied_aux = NULL;
	switch(src->operations->type){
		case VM_UNINIT:
			uninit_case_copied_aux = malloc(sizeof(struct vm_initializer_aux));
			memcpy(uninit_case_copied_aux, src->uninit.aux, sizeof(struct vm_initializer_aux));
			uninit_new(dst, src->va, src->uninit.init, src->uninit.type, uninit_case_copied_aux, src->uninit.page_initializer);
			dst->writable = src->writable;
			break;
		default:
			//For anon, claim memory immediately.
            //여기서 uninit을 만드는 가장 중요한 이유는 anon과 file의 경우에 vm_do_claim_page를 바로 하게 되면 parent process의 내용을 긁어 오는게 아니라
            //file을 다시 로드 한다는 점. 왜냐하면 page.swap_in이 실행횔 때, anon의 경우 anon_swap_in임(uninit의 경우 uninit_initializer)
            //따라서 uninit page로 initialize하여 vm_do_claim_page에서 swap_in이 page_cont_copy가 되게 하여 parent process
            //의 내용을 긁어 오게 만든다.
			uninit_new(dst, src->va, page_cont_copy, src->operations->type, src, 
				(src->operations->type == VM_ANON) ? anon_initializer : file_backed_initializer
			);
			dst->writable = src->writable;
			vm_do_claim_page(dst);
			break;
	}
    

}
/*void
_spt_entry_copy (struct page *dst, struct page *src) {
	//1. (Shallow) Copy all the things
	memcpy(dst, src, sizeof(struct page));
	//2. Remove some 'NOT BE SAME' values
	dst->frame = NULL;
	dst->elem.list_elem.next = NULL;
	dst->elem.list_elem.prev = NULL;
	//3. Treat different cases
	switch(src->operations->type){
		case VM_UNINIT:
			//For uninit(not yet loaded on memory), not get frames immediately.
			struct vm_initializer_aux *copied_aux = malloc(sizeof(struct vm_initializer_aux));
			memcpy(copied_aux, src->uninit.aux, sizeof(struct vm_initializer_aux));
			dst->uninit.aux = copied_aux;
			break;
		case VM_ANON:
			//For anon, claim memory immediately.
			vm_do_claim_page(dst);
			//Problem. CONTENT DIFFERS!
			break;
		case VM_FILE:
			PANIC("NOT YET");
			break;
	}
    

}*/