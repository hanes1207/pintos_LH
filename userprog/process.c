#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"

#include "devices/input.h"
#ifdef VM
#include "vm/vm.h"
#endif

#define SAFE_LOCK_FILESYS(code) lock_acquire(&file_lock); code lock_release(&file_lock);


static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

struct fork_aux{
	struct thread* parent;			//Context-switching saved context
	struct intr_frame* parent_if;	//Definitely User-space context(from system call)
};


struct lock file_lock;	//Global Filesystem lock

static void
process_file_map_init(struct thread* th){
	th->file_map = (struct file**)malloc(sizeof(struct file*) * FILE_DESC_MAP_SIZE);
	th->file_map[0] = NULL;	//STDIN
	th->file_map[1] = NULL;	//STDOUT
	th->file_next_desc = 2;
	for(int i=2; i<FILE_DESC_MAP_SIZE; ++i){
		th->file_map[i] = NULL;
	}
}

static void
process_file_map_free(struct thread* th){
	lock_acquire(&file_lock);
	for(int i=2; i<th->file_next_desc; ++i){
		if(th->file_map[i] != NULL)
			file_close(th->file_map[i]);
	}
	lock_release(&file_lock);
	th->file_next_desc = 2;
	free(th->file_map);
}

static void
process_file_map_duplicate(struct thread* target, const struct thread* original){
	//process_file_map_init(target);
	target->file_next_desc = original->file_next_desc;

	lock_acquire(&file_lock);
	for(int i=2; i<original->file_next_desc; ++i){
		target->file_map[i] = file_duplicate(original->file_map[i]);
	}
	lock_release(&file_lock);
}

static int process_get_new_fd(struct thread* target){
	const int ret_fd = target->file_next_desc;
	target->file_next_desc++;
	return ret_fd;
}
static bool process_check_fd(struct thread* target, int fd){
	if(fd < 2 || fd > FILE_DESC_MAP_SIZE){
		return false;
	}
    else if (target->file_map[fd] == NULL) {
        return false;
    }
	//printf("process_check_fd:next_fd=%d\n", target->file_next_desc);
	//printf("process_check_fd:fd=%d, true\n", fd);
	return true;
}
bool process_create_file(struct thread* target, const char* file, unsigned initial_size){
	bool ret_val = false;
	SAFE_LOCK_FILESYS(
		ret_val = filesys_create(file, initial_size);
	)
	return ret_val;
}
bool process_remove_file(struct thread* target, const char* file){
	bool ret_val = false;
	SAFE_LOCK_FILESYS(
		ret_val = filesys_remove(file);
	)
	return ret_val;
}
int process_open_file(struct thread* target, const char* file){
	struct file* open_file = NULL;
	SAFE_LOCK_FILESYS(
		open_file = filesys_open(file);
	)
	if(open_file == NULL){
		return -1;
	}
	const int ret_fd = process_get_new_fd(target);
	target->file_map[ret_fd] = open_file;
	return ret_fd;
}
int process_filesize(struct thread* target, int fd){
	if(!process_check_fd(target, fd)){
		return -1;
	}
	int file_size = 0;
	SAFE_LOCK_FILESYS(
		file_size = file_length(target->file_map[fd]);
	)
	return file_size;
}
int process_read(struct thread* target, int fd, void* buffer, unsigned size){
	if(fd == STDIN_FILENO){
		for(int i=0; i<size; ++i){
			((char*)buffer)[i] = input_getc();
		}
	}
	else if(!process_check_fd(target, fd)){
		return -1;
	}
	int ret_val;
	SAFE_LOCK_FILESYS(
		ret_val = file_read(target->file_map[fd], buffer, size);
	)
	return ret_val;
}
int process_write(struct thread* target, int fd, const void* buffer, unsigned size){
	if(fd == STDOUT_FILENO){
		putbuf(buffer, size);
		return size;
	}
	else if(!process_check_fd(target, fd)){
		return -1;
	}
	int ret_val;
	SAFE_LOCK_FILESYS(
		ret_val = file_write(target->file_map[fd], buffer, size);
	)
	return ret_val;
}
void process_seek(struct thread* target, int fd, unsigned position){
	if(!process_check_fd(target, fd)){
		return;
	}
	SAFE_LOCK_FILESYS(
		int file_size = file_length(target->file_map[fd]);
		if(file_size < position)
			file_seek(target->file_map[fd], position);
	)
}
unsigned process_tell(struct thread* target, int fd){
	if(!process_check_fd(target, fd)){
		return 0;
	}
	unsigned ret_val;
	SAFE_LOCK_FILESYS(
		ret_val = file_tell(target->file_map[fd]);
	)
	return ret_val;
}
void process_close(struct thread* target, int fd){
	if(!process_check_fd(target, fd)){
		return;
	}
	SAFE_LOCK_FILESYS(
		//printf("process_close : fd=%d\n",fd);
		file_close(target->file_map[fd]);
		target->file_map[fd] = NULL;
	)
}

char* process_get_exec_filename(const char* file_name){
	//결국엔 malloc을 한 번은 써 주어야만 했다..... 
	//이럴 거면 애초에 아래에서 strtok로 뒤집는 저 X랄을 할 필요가...
	const int cmdlen = strlen(file_name);
	int end_pos = 0;
	for(int i=0; i<cmdlen; ++i){
		//printf("%d -> [%c]\n", i, file_name[i]);
		if(file_name[i] == ' ' || file_name[i] == '\t' || file_name[i] == '\n'){
			end_pos = i;
			break;
		}
	}
	if(end_pos == 0)
		end_pos = cmdlen;
	
	char* exec_file_name = malloc(end_pos + 1);
	memcpy(exec_file_name, file_name, end_pos);
	exec_file_name[end_pos] = '\0';
	//printf("process_get_filename() -> %s\n", exec_file_name);
	return exec_file_name;
}

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
	process_file_map_init(current);
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
	lock_init(&file_lock);

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	/* Create a new thread to execute FILE_NAME. */
	char* exec_file_name = process_get_exec_filename(file_name);
	tid = thread_create (exec_file_name, PRI_DEFAULT, initd, fn_copy);
	free(exec_file_name);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_) {
	/* Clone current thread to new thread.*/
	//printf("process_fork():if: rip=%llx, cs=%d\n", if_->rip,if_->cs);
	struct fork_aux* aux = malloc(sizeof(struct fork_aux));
	aux->parent= thread_current();
	aux->parent_if = if_;

	return thread_create (name,
			PRI_DEFAULT, __do_fork, aux);
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
	if(is_kernel_vaddr(va)){
		return true;
	}

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER);

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		// Page Table에 쓸 추가적인 메모리가 없으면 에러가 난다는데...
		//-> 그래서 어쩌라, 메모리를 창조해서 넣어주랴...
		puts("ERROR HANDLING NEEDED!");
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
	struct thread *parent = ((struct fork_aux*)aux)->parent;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = ((struct fork_aux*)aux)->parent_if; // update register
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	//printf("parent_if : rip=%llx, cs=%d\n", parent_if->rip, parent_if->cs);
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	if_.R.rax = 0;	//MUST RETURN 0 FOR CHILD.

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
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	process_init ();
	// file duplicate
	SAFE_LOCK_FILESYS(
	if(parent->exec_file != NULL)
		current -> exec_file = file_duplicate(parent->exec_file);	/*ROX-CHILD, ROX-MULTICHILD*/
	)
    process_file_map_duplicate(current, parent);

	free(aux);
	sema_up(&parent->fork_sema);
	//printf("__do_fork() : tid=%d, return=%d, rip=%llx, succ=%d, cs=%d, cs(now)=%d\n", current->tid, if_.R.rax, if_.rip, succ,if_.cs, current->tf.cs);
	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	const int f_name_len = strlen(f_name);
	char* file_name = palloc_get_page(PAL_ZERO);
	memcpy(file_name, f_name, f_name_len + 1);
	
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	//process_file_map_free and init commented due to policy.
	//process_file_map_free(thread_current());
	SAFE_LOCK_FILESYS(
		//기존의 실행 파일은 닫는다.
		if(thread_current()->exec_file != NULL){
			file_close(thread_current()->exec_file);
		}
	)
	process_cleanup ();
	//printf("file_name : %s\n", file_name);
	/* And then load the binary */
	success = load (file_name, &_if);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success){
		return -1;
	}
		
	//process_file_map_init(thread_current());
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
process_wait (tid_t child_tid) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	//printf("WAIT FOR %d\n", child_tid);
	struct thread* curr = thread_current();
	lock_acquire(&curr->child_procs_lock);
	for(
		struct list_elem* cursor = list_begin(&curr->child_procs);
		cursor != list_end(&curr->child_procs);
		cursor = list_next(cursor)
	){
		struct thread* target = list_entry(cursor, struct thread, proc_elem);
		if(target->tid == child_tid){
			lock_release(&curr->child_procs_lock);
			//puts("Parent hang on wait_hang_sema");
			sema_down(&target->wait_hang_sema);
			const int exit_code = target->exit_code;
			//puts("Parent let child to be freed");
			sema_up(&target->res_free_sema);
			sema_down(&target->switch_to_child_sema);
			//Removing from list is done by child itself.
			return exit_code;
		}
	}
	//Default is -1.
	lock_release(&curr->child_procs_lock);
	return -1;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	//Allow all child's resource free before die
	lock_acquire(&curr->child_procs_lock);
	for(
		struct list_elem* it=list_begin(&curr->child_procs);
		it != list_end(&curr->child_procs);
		it = list_next(it)
	){
		struct thread* child = list_entry(it, struct thread, proc_elem);
		child->parent = NULL;
		sema_up(&child->res_free_sema);
	}
	lock_release(&curr->child_procs_lock);

	//Allow parent's wait ends
	
	sema_up(&curr->wait_hang_sema);
	//After getting resource_free_semaphore(allow for exit from parent, means wait called.)
	//puts("Child hang on res_free_sema");
	sema_down(&curr->res_free_sema);
	//puts("Child pass res_free_sema");
	process_file_map_free(curr);

	lock_acquire(&file_lock);
	if(curr->exec_file != NULL)
		file_close(curr->exec_file);
	lock_release(&file_lock);

	if(curr->parent != NULL){
		lock_acquire(&curr->parent->child_procs_lock); // prevent sibbiling from accessing parent
		list_remove(&curr->proc_elem); //Critical section
		lock_release(&curr->parent->child_procs_lock);

		sema_up(&curr->switch_to_child_sema);
	}
	printf ("%s: exit(%d)\n", curr->name, curr->exit_code);
	process_cleanup ();
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
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	char* exec_file_name = process_get_exec_filename(file_name);
	/* Open executable file. */
	lock_acquire(&file_lock);
	file = filesys_open (exec_file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", exec_file_name);
		free(exec_file_name);
		goto done;
	}
	//For denying write on exec.
	t->exec_file = file;
	file_deny_write(t->exec_file);

	free(exec_file_name);
	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
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
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	
	//# ---- Process arguments(1) ---- #
	//What is input? -> file_name is command(...)
	//Use if_'s rsp to manipulate stack

	//Copy whole command into user program's stack, and then tokenize
	const int cmd_len = strlen(file_name);
	const int cmd_size = cmd_len + 1;
	const int alignment = (8 - (cmd_size & 0b111)) & 0b111;

	//Manipulate RSP for copying string
	if_->rsp -= cmd_size;
	char* cmd_copy = (void*)(if_->rsp);
	memcpy(cmd_copy, file_name, cmd_size);

	//Manipulate RSP for alignment
	if_->rsp -= alignment;

	int argc = 0;
	char* cur = NULL;
	for(
		char* ret_ptr = strtok_r(cmd_copy, " ", &cur);
		ret_ptr;
		ret_ptr = strtok_r(NULL, " ", &cur)
	){
		if_->rsp -= sizeof(void*);
		*((char**)if_->rsp) = ret_ptr;

		argc++;
	}
	//printf("load() : argc = %d\n",argc);
	if_->rsp -= sizeof(void*);
	*((char**)if_->rsp) = NULL;
	//# ---- Process arguments(1) End ---- #
	//Still, argv[i] needs to be reversed.


	char** argv_start = (char**)if_->rsp;
	//Reverse order : 
	//	From now on, stack has 	(Top) {0, 1, 2, 3, 4} (Bottom)
	//	It should be : 			(Top) {4, 3, 2, 1, 0} (Bottom)
	
	for(int i=0; i <= argc / 2; ++i){
		//printf("Swap [%d] : [%s](%d) & [%s](%d)\n", i, *(argv_start + i), i, *(argv_start + argc - i), argc - i);
		char* temp_ptrval = *(argv_start + i);
		*(argv_start + i) = *(argv_start + argc - i);
		*(argv_start + argc - i) = temp_ptrval;
	}
	//Return Addr(NULL)
	if_->rsp -= sizeof(void*);
	*((void**)if_->rsp) = NULL;

	if_->R.rdi = argc;	//argc(int)
	if_->R.rsi = (uint64_t)(if_->rsp + 8);	//argv(char*[])
	
	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	//Originally, it should close file here, but for denying writes on exec.
	//	We close file in process_exit, after res_free_sema()

	//file_close (file);
	lock_release(&file_lock);
	return success;
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
			printf("fail\n");
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

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
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

	return success;
}
#endif /* VM */
