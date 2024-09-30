#include "threads/thread.h"
#include "threads/fixed_point.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Project 1-3 변수 관리
 * 1. mlfqs_i_ready_threads 
 *   - thread_yield()		-> running thread가 ready가 되므로 +1
 *   - next_thread_to_run() -> ready 중 하나가 running이 되므로 -1
 *   - thread_unblock()		-> ready thread 추가되므로 +1
 * 
 * 2. mlfqs_fp_load_avg		-> thread_tick에서 관리
 * 
 * 3. mlfqs_max_priority	-> 대기 중인 스레드의 max_priority가 의미가 있는데, 이를 하다보면
 * 너무 할 게 늘어난다. -> 때려쳐
 *  --> bsd reschedule 할 때
 *  --> set_nice 할 때
 *  --> 새 thread 생성 o
 * 
 * 4. mlfqs_ready_list		-> 기존에 ready_list을 쓰던 모든 부분을 대체해야 함.
 * 		-> thread_unblock
 * 		-> thread_yield
 * 		-> next_thread_to_run
 * 		
 * ToDo
 * thread yield --> cpu 양보하기 전에 나를 넣어놓고 가야 한다.
 * sema up - 깨어난 놈의 priority를 체크해야 한다.
 * next_thread_to_run - ready list로 되어 있던데 고쳐야 하고
 */

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;
//static int mlfqs_max_priority;
static struct list mlfqs_ready_list[64];
static struct list sleep_list; // List of processes in sleeping

bool comp_wake_ticks (const struct list_elem *a,
                            const struct list_elem *b,
                            void *aux UNUSED);
bool comp_priority (const struct list_elem *a,
                            const struct list_elem *b,
                            void *aux UNUSED);

// BSD Scheduler helper functions
static void bsd_recalculate_priorities(void);
void update_recent_cpu_per_sec_ready_list(void);
void update_recent_cpu_per_sec (struct thread *t);
void update_recent_cpu_per_tick (void);
void update_load_avg (void);
int  thread_get_bsd_priority(const struct thread *t);

//Interrupts must be disabled for these mlfqs helper methods.
static struct thread* mlfqs_next_to_run();
static int mlfqs_ready_list_max_priority (void);
void mlfqs_insert_thread(struct thread* t);


/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;
static int mlfqs_fp_load_avg;
static int mlfqs_i_ready_threads;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	for(int i=PRI_MIN; i<=PRI_MAX; i++){
		list_init(&mlfqs_ready_list[i]);
	}
    list_init (&sleep_list);
	list_init (&destruction_req);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
	if(thread_mlfqs){
		//Initialize root thread's niceness
		initial_thread->mlfqs_i_nice = 0;

		//Initialize global info.
		mlfqs_fp_load_avg = 0;
		mlfqs_i_ready_threads = 0;
	}
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();
    struct list_elem *e = list_begin (&sleep_list);
    struct thread *tmp;
    int64_t curr_ticks = timer_ticks ();

	if(thread_mlfqs)
		ASSERT(list_empty(&ready_list));

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;
    for (
        e = list_begin(&sleep_list);
        e != list_end(&sleep_list);
    ) {
        tmp = list_entry (e, struct thread, elem);

        if (tmp->wake_ticks <= curr_ticks) {
            ASSERT(tmp->status == THREAD_BLOCKED);
            list_pop_front(&sleep_list);
            e = list_begin(&sleep_list);
            thread_unblock (tmp);
        }
        else break;
    }

    if (thread_mlfqs) {
        update_recent_cpu_per_tick ();
        if ((curr_ticks % TIMER_FREQ) == 0) {
            // load avg 변경
			update_load_avg();
            // 모든 스레드의 recent cpu 변경
			update_recent_cpu_per_sec(thread_current());
			update_recent_cpu_per_sec_ready_list();
        }
        if ((curr_ticks % 4) == 0) {
            // 모든 스레드의 priority 업데이트
			bsd_recalculate_priorities();
        }
    }

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	if(thread_mlfqs){
		t->mlfqs_i_nice = thread_get_nice();
		t->mlfqs_fp_recent_cpu = 0;
	}

	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	enum intr_level old_level = intr_disable();
	thread_unblock (t);

	if(!thread_mlfqs){
		//Priority Scheduler
    	if (thread_get_priority () < priority)
        	thread_yield ();
	} else {
		//BSD Scheduler(mlfqs)
		if(thread_get_priority() < thread_get_bsd_priority(t)){
			thread_yield ();
		}
	}
	intr_set_level(old_level);
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	if(thread_mlfqs)
		mlfqs_i_ready_threads--;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	if(thread_mlfqs){
		//TODO : Insert into appropriate queue.
		mlfqs_i_ready_threads++;
		mlfqs_insert_thread(thread_current());
	}
	else {
		list_insert_ordered (&ready_list, &t->elem, comp_priority, NULL);
	}
	t->status = THREAD_READY;
		
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

bool
comp_wake_ticks (const struct list_elem *a,
                const struct list_elem *b, void *aux UNUSED) {
    struct thread *thread_a = list_entry (a, struct thread, elem);
    struct thread *thread_b = list_entry (b, struct thread, elem);

    return thread_a->wake_ticks < thread_b->wake_ticks;
}
bool
comp_priority (const struct list_elem *a,
                const struct list_elem *b, void *aux UNUSED) {
    struct thread *thread_a = list_entry (a, struct thread, elem);
    struct thread *thread_b = list_entry (b, struct thread, elem);

    int priority_a = thread_get_arbitrary_priority (thread_a);
    int priority_b = thread_get_arbitrary_priority (thread_b);

    return (priority_a > priority_b);
}

void
thread_sleep (void) {
    struct thread *curr = thread_current ();
    enum intr_level old_level;

    ASSERT (!intr_context ());
    old_level = intr_disable ();
    if (curr != idle_thread) {
        list_insert_ordered (&sleep_list, &curr->elem, comp_wake_ticks, NULL);
        thread_block();
    }
    intr_set_level (old_level);
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread){
		if(!thread_mlfqs){
			//Priority Scheduling Case
			list_insert_ordered(&ready_list, &curr->elem, comp_priority, NULL);
		} else {
			//TODO : mlfqs Case
			mlfqs_i_ready_threads++;
			//list_push_back (&ready_list, &curr->elem);
			mlfqs_insert_thread(thread_current());
		}
	}
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	if(!thread_mlfqs){
		//If priority change for this thread makes difference in max(ready_list->priority),
		//	Then this thread should yield.
		struct thread* curr = thread_current ();
		struct list_elem *e = list_begin (&sleep_list);
		struct thread *tmp = list_entry (e, struct thread, elem);
		int priority_tmp = tmp->priority;
		int dpriority_tmp = tmp->dpriority;

		curr->priority = new_priority;
		if (new_priority < priority_tmp || new_priority < dpriority_tmp) {
			thread_yield ();
		}
	} else {
		// TODO : mlfqs
		// DO NOTHING
	}
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	if(!thread_mlfqs){
		//Priority Scheduler
		//For priority donation implementation, 
		//	This function should calculate its priority using "donated" priorities.
		struct thread *t = thread_current();
    	return thread_get_arbitrary_priority (t);
	} else {
		//TODO : mlfqs
		// Calculate its priority.
		return thread_get_bsd_priority(thread_current());
	}
}
int
thread_get_bsd_priority(const struct thread *t){
	ASSERT(t != NULL && "Thread pointer should not null");
	const int recent_cpu_section = TO_INTEGER(t->mlfqs_fp_recent_cpu / 4);
	return PRI_MAX - recent_cpu_section - (t->mlfqs_i_nice * 2);
}

/* Returns the current thread's priority. */
int
thread_get_arbitrary_priority (const struct thread *t) {
	//TODO : For priority donation implementation, 
	//	This function should calculate its priority using "donated" priorities.
    int priority = t->priority;
    int dpriority = t->dpriority;

	return (priority > dpriority ? priority : dpriority);
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) {
	/* TODO: Your implementation goes here */
    struct thread *curr = thread_current();
    curr->mlfqs_i_nice = nice;

    enum intr_level old_level = intr_disable();
	curr->priority = thread_get_bsd_priority(curr);

	const int ready_max_priority = mlfqs_ready_list_max_priority();
	if(curr->priority < ready_max_priority){
		thread_yield();
	}
	intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
    struct thread *curr = thread_current();

	return curr->mlfqs_i_nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */

	return TO_INTEGER(mlfqs_fp_load_avg * 100);
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	return TO_INTEGER(thread_current()->mlfqs_fp_recent_cpu * 100);
}

void
update_recent_cpu_per_sec_ready_list(void){
	for(int i=0; i<64; ++i){
		if(!list_empty(&mlfqs_ready_list[i])){
			for(
				struct list_elem* cur = list_begin(&mlfqs_ready_list[i]);
				cur != list_end(&mlfqs_ready_list[i]);
				cur = list_next(cur)
			){
				struct thread* target_thread = list_entry(cur, struct thread, elem);
				update_recent_cpu_per_sec(target_thread);
			}
		}
	}
}

void
update_recent_cpu_per_sec (struct thread *t) {
    int numerator = 2 * mlfqs_fp_load_avg;
    int denominator = 2 * mlfqs_fp_load_avg + TO_FIXED_POINT(1);
    int weight = FIXED_DIV(numerator, denominator);
    int past_weighted = FIXED_MULT(weight, t->mlfqs_fp_recent_cpu);

    t->mlfqs_fp_recent_cpu += TO_FIXED_POINT(thread_get_nice());
}

void
update_recent_cpu_per_tick (void) {
    struct thread *curr = thread_current ();
    curr->mlfqs_fp_recent_cpu += TO_FIXED_POINT(1);
}

void
update_load_avg (void) {
    mlfqs_fp_load_avg *= 59;
    mlfqs_fp_load_avg += mlfqs_i_ready_threads;

    mlfqs_fp_load_avg /= 60;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);

	if(!thread_mlfqs)
		t->priority = priority;	//Priority
	else
		t->priority = thread_get_bsd_priority(t);	//mlfqs

    t->dpriority = PRI_MIN;
	t->magic = THREAD_MAGIC;

	list_init(&t->locks);
	t->lock_ptr = NULL;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if(!thread_mlfqs){
		if (list_empty (&ready_list))
			return idle_thread;
		else{
			if(!thread_mlfqs){
				//Priority Scheduling
				return list_entry (list_pop_front (&ready_list), struct thread, elem);
			}
		}
	} else {
		//TODO : mlfqs
		mlfqs_i_ready_threads--;
		return mlfqs_next_to_run();
	}
}

static struct thread*
mlfqs_next_to_run(){
	for(int i=PRI_MAX; i>= PRI_MIN; --i){
		if(!list_empty(&mlfqs_ready_list[i])){
			return list_entry (list_pop_front (&mlfqs_ready_list[i]), struct thread, elem);
		}
	}
	ASSERT(false && "mlfqs_next_to_run() : Should not reach");
	return NULL;
}
static int
mlfqs_ready_list_max_priority (void){
	struct thread* max_pri_thread = mlfqs_next_to_run();
    if (max_pri_thread == NULL){
        return PRI_MIN;
    } else {
        return max_pri_thread->priority;
    }
}

void mlfqs_insert_thread(struct thread* t){
	const int priority = thread_get_bsd_priority(t);
	ASSERT(PRI_MIN <= priority && priority <= PRI_MAX && "PRIORITY OUT OF RANGE");

	list_push_back(&mlfqs_ready_list[priority], &t->elem);
}
/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (next != NULL);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

//BSD Scheduler
static void
bsd_recalculate_priorities(void) {
	//TODO : For all 64 ready lists use for loop and recalculate them and reinsert them.
	struct list temp_list;
	for(int i=0; i<64; ++i){
		if(!list_empty(&mlfqs_ready_list[i])){
			struct list_elem *next = NULL;
			for(
				struct list_elem* cur = list_begin(&mlfqs_ready_list[i]);
				cur != list_end(&mlfqs_ready_list[i]);
				cur = next
			){
				//1. 일단은 꺼낸다.
				next = list_next(cur);
				list_remove(cur);

				//2. 일단 temp_list에 집어넣는다.
				list_push_back(&temp_list, cur);

				//3. Priority를 계산한다.
				struct thread* target_thread = list_entry(cur, struct thread, elem);
				target_thread->priority = thread_get_bsd_priority(target_thread);
			}
		}
	}

	struct list_elem* next = NULL;
	for(
		struct list_elem* cur = list_begin(&temp_list);
		cur != list_end(&temp_list);
		cur = next
	){
		//Temp_list에서 하나씩 뽑아서 각자의 priority에 해당하는 queue로 집어넣는다.
		next = list_next(cur);
		list_remove(cur);

		struct thread* target_thread = list_entry(cur, struct thread, elem);
		int target_priority = target_thread->priority;
		ASSERT(0<= target_priority && target_priority < 64);

		list_push_back(&mlfqs_ready_list[target_priority], cur);
	}
}