#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

int syscall_get_page_cnt(const void* target_ptr, size_t length){
	uint64_t pg_cnt = (uint64_t)target_ptr;
    pg_cnt &= PGMASK;
    uint64_t tail = (uint64_t)target_ptr & PGMASK;
    tail = !!(tail);
    pg_cnt += length;
    pg_cnt >>= 12;
    pg_cnt += tail;
    return pg_cnt;
	//return (length >> 12) + (length & PGMASK);
}
bool
syscall_memcheck(const void* target_ptr, size_t length){
	const struct thread* current = thread_current();

	if(target_ptr == NULL)
		return false;
	uint64_t target_ptr_val = (uint64_t)target_ptr;
	if(target_ptr_val >= KERN_BASE || target_ptr_val + length >= KERN_BASE){
		return false;
	}
	//Else, check userspace page table entries.
	const int page_cnt = syscall_get_page_cnt(target_ptr, length);
	for(int i=0; i<page_cnt; ++i){
		if(pml4e_walk(current->pml4, target_ptr_val + i * PGSIZE, 0) == NULL){
			return false;
		}
	}
	return true;
}
bool syscall_create(const char* path, unsigned initial_size){
	if(!syscall_memcheck(path, 1)){
		thread_exit();
	}
}
int syscall_open(const char* path){
    
}
int syscall_close(int fd){
	
}
int syscall_read(int fd, void* buffer, unsigned size){
	//1. Check user memory(buffer and size)
	if(!syscall_memcheck(buffer, size)){
		thread_exit();
	}
}
int syscall_write(int fd, const void* buffer, unsigned size){
	//1. Check user memory(buffer and size)
	if(!syscall_memcheck(buffer, size)){
		thread_exit();
	}
	//2. Do actions.
	if(fd == 0){
		return 0;
	}
	else if(fd == 1){
		//Write into console.
		putbuf(buffer, size);
	}
	else{
		//File operations

	}
}
/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	const int64_t syscall_num = f->R.rax;
	uint64_t syscall_args[6] = {0,};
	syscall_args[0] = f->R.rdi;
	syscall_args[1] = f->R.rsi;
	syscall_args[2] = f->R.rdx;
	syscall_args[3] = f->R.r10;
	syscall_args[4] = f->R.r8;
	syscall_args[5] = f->R.r9;

	switch(syscall_num){
		//Project 2
		case SYS_HALT:
			power_off();
			NOT_REACHED();
			break;

		case SYS_EXIT:
			{
				const int status = syscall_args[0];
            	thread_current()->exit_code = status;
				thread_exit(); //Free all res. however, child status block should remain.
			}
			break;
		
		case SYS_FORK:
			f->R.rax = 0;
			//printf("SYS_FORK : rip=%llx, cs=%d\n",f->rip,f->cs);
			const tid_t child_tid = process_fork((const char*)(syscall_args[0]), f);
			//Return value differs. (parent vs child)
			sema_down(&thread_current()->fork_sema);
			if(child_tid != thread_current()->tid)
				f->R.rax = child_tid;
			break;
		
		case SYS_EXEC:
			f->R.rax = process_exec((const char*)(syscall_args[0]));
			break;
		
		case SYS_WAIT:
			f->R.rax = process_wait(syscall_args[0]);
			break;
		
		case SYS_CREATE:
			f->R.rax = syscall_create(syscall_args[0], syscall_args[1]);
			break;
		
		case SYS_REMOVE:
			//f->R.rax = /*TODO*/;
			break;
		
		case SYS_OPEN:
			f->R.rax = syscall_open(syscall_args[0]);
			break;
		
		case SYS_FILESIZE:

			break;
		
		case SYS_READ:
			f->R.rax = syscall_read(syscall_args[0], syscall_args[1], syscall_args[2]);
			break;
		
		case SYS_WRITE:
			f->R.rax = syscall_write(syscall_args[0], (const void*)syscall_args[1], syscall_args[2]);
			break;
		
		case SYS_SEEK:

			break;
		case SYS_TELL:

			break;
		
		case SYS_CLOSE:

			break;
		//Project 3, 4
		default:
			//Invalid system calls.
			break;
	}
	//printf ("system call!\n");
	//thread_exit ();
}

void
sys_exit_handler (int status) {
    
}