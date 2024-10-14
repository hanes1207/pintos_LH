#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"

#ifdef USERPROG
#include "threads/synch.h"
#endif
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

// Thread Niceness(mlfqs)
#define NICE_MIN -20
#define NICE_MAX 20
#define NICE_DEFAULT 0

#define FILE_DESC_MAP_SIZE 256


struct CSB{
	//Child Status Block
	tid_t tid;
	int exit_status;
	struct semaphore wait_hang_sema;
	struct list_elem elem;
	struct thread* thread_ptr;
};
/* thread_create_child_status_block()
 * -> Create child_status_block(via malloc())
 * -> Add child_status_block in parent's csb_list
 * -> Set child thread's csb_pointer to CSB.
 * 
 * Note. If parent process dies first, then it should set all child's csb_pointer to NULL
 * Note. If child process exited, then it set its csb's thread pointer to NULL
 * Note. NULL pointer means do nothing for that.(Orphan process, )
 */
void thread_create_child_status_block(struct thread* parent, struct thread* child);
void thread_free_csb_list(struct thread* target);	//Sweep csb_list, mark those thread's csb_pointer to NULL, free all the items in list.
void thread_detach_csb(struct thread* target);		//Go to csb, mark its thread_ptr to NULL

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
    int64_t wake_ticks;                 /* tick leftover until wake up */

	//TODO : Need to save donated priorities.
	int dpriority;	
		//lock_acquire & lock_release is responsible 
		//for call 
		//		(acquire) thread_dpriority_update_acquire(struct thread* th, int new_dpriority);
		//		(release) thread_dpriority_update_release(struct thread* th, struct list * waiters);
		//For acquire case, update must be done BEFORE sema_down();	(sema_down stalls this thread)
		//For release case, update must be done AFTER sema_up();	(sema_up makes change in waiters)
		//For both case, for dpriority change, like priority change,
		//	If this thread is no longer "max-priority thread", then yield immediately
		//	-> Only release case can change priority and if dpriority is same, then just go on.
	
	/* For mlfqs */
	int mlfqs_i_nice;
	int mlfqs_fp_recent_cpu;

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */
	struct list_elem mlfqs_elem;		//For sema_waiters_list
    struct list locks;                  /*  Holding locks
											For Priority donation return(If 2 locks made donation, 
                                            then 1 lock released, other lock's donation info must be present. */
    void *lock_ptr;						// Lock's pointer who stalls this thread.

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
	
	bool is_process;
	struct thread* parent;
	struct lock child_procs_lock;
	struct list child_procs;					// Child processes
	struct list_elem proc_elem;

	int exit_code;
	struct semaphore wait_hang_sema;        // modifying wait_hang_sema must preceed modifying res_free_sema
	struct semaphore res_free_sema;

	struct semaphore switch_to_child_sema;
	struct semaphore fork_sema;
	
	struct file* exec_file;
	struct file** file_map;
	int file_next_desc;

	tid_t fork_child_tid;
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;
extern struct list sema_waiters_list;	// List of semaphores

void thread_init (void);
void thread_start (void);
void thread_print_ready_queue(void);
void thread_print_block_queue();

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_sleep (void);
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);
int thread_get_arbitrary_priority (const struct thread * t);

bool
comp_priority (const struct list_elem *a,
                const struct list_elem *b, void *aux);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

#endif /* threads/thread.h */
