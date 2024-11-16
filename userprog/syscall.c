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
	uint64_t target_ptr_vaddr = (uint64_t)target_ptr;
	uint64_t padding = PGSIZE - target_ptr_vaddr & PGMASK;

	int page_cnt = 0;
	if(padding != PGSIZE){
		page_cnt++;
		target_ptr_vaddr += padding;
	}
	page_cnt += (length / PGSIZE);
	if(length % PGSIZE != 0){
		page_cnt ++;
	}
	return page_cnt;

	/*uint64_t pg_cnt = (uint64_t)target_ptr;
    pg_cnt &= PGMASK;
    uint64_t tail = (uint64_t)target_ptr & PGMASK;
    tail = !!(tail);
    pg_cnt += length;
    pg_cnt >>= 12;
    pg_cnt += tail;
    // printf("tail: %d\n", tail);
    return pg_cnt;*/
	//return (length >> 12) + (length & PGMASK);
}
bool
syscall_memcheck_str(const char* target_str){
	const struct thread* current = thread_current();
	const uint64_t target_str_vaddr = (uint64_t) target_str;
	if(target_str == NULL)
		return false;
	if(is_kernel_vaddr(target_str_vaddr))
		return false;
	
	//Else, check userspace page table entries and 
	//check string length.
	const max_page_cnt = 2;
	int page_present = 2;
	for(int i=0; i<max_page_cnt; ++i){
		if(pml4e_walk(current->pml4, target_str_vaddr + i * PGSIZE, 0) == NULL){
			page_present = i;
			break;
		}
	}
	//printf("page_present : %d\n", page_present);
	int max_str_len = 0;
	if(page_present == 0){
		return false;
	}
	else if(page_present == 1){
		//1 page
		max_str_len = PGSIZE - (target_str_vaddr & PGMASK);
	}else{
		//2 pages
		max_str_len = PGSIZE;
	}
    //Check null termination
	//printf("max_str_len = %d, strnlen(target_str, max_str_len) = %d\n", max_str_len, strnlen(target_str, max_str_len));
	return max_str_len != strnlen(target_str, max_str_len);
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
	//printf("syscall_memcheck:page_cnt=%d\n", page_cnt);
	for(int i=0; i<page_cnt; ++i){
		if(pml4e_walk(current->pml4, target_ptr_val + i * PGSIZE, 0) == NULL){
			return false;
		}
	}
	//puts("syscall_memcheck()->true");
	return true;
}
bool syscall_create(const char* path, unsigned initial_size){
	if(!syscall_memcheck_str(path)){
		thread_exit();
	}
	return process_create_file(thread_current(), path, initial_size);
}
bool syscall_remove(const char* file){
	if(!syscall_memcheck_str(file)){
		thread_exit();
	}
	return process_remove_file(thread_current(), file);
}
int syscall_open(const char* path){
    if(!syscall_memcheck_str(path)){
		thread_exit();
	}
	return process_open_file(thread_current(), path);
}
int syscall_filesize(int fd){
	return process_filesize(thread_current(), fd);
}
int syscall_read(int fd, void* buffer, unsigned size){
	//1. Check user memory(buffer and size)
	if(!syscall_memcheck(buffer, size)){
		thread_exit();
	}
	return process_read(thread_current(), fd, buffer, size);
}
int syscall_write(int fd, const void* buffer, unsigned size){
	//1. Check user memory(buffer and size)
	if(!syscall_memcheck(buffer, size)){
		thread_exit();
	}
	//2. Do actions.
	return process_write(thread_current(), fd, buffer, size);
}
void syscall_seek(int fd, unsigned position){
	process_seek(thread_current(), fd, position);
}
unsigned syscall_tell(int fd){
	return process_tell(thread_current(), fd);
}
void syscall_close(int fd){
	//printf("syscall_close : fd=%d\n", fd);
	process_close(thread_current(), fd);
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

	//printf("SYSCALL %ld(read=%ld)\n", syscall_num, SYS_READ);
	thread_current()->rsp = f->rsp;
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
			if(!syscall_memcheck_str(syscall_args[0])){
				thread_exit();
			}
			//printf("SYS_FORK : rip=%llx, cs=%d\n",f->rip,f->cs);
			f->R.rax = process_fork((const char*)(syscall_args[0]), f);
			break;
		
		case SYS_EXEC:
			if(!syscall_memcheck_str(syscall_args[0])){
				thread_exit();
			}
			f->R.rax = process_exec((const char*)(syscall_args[0]));
			thread_exit();
			//printf("exec() failed : %d\n", f->R.rax);
			break;
		
		case SYS_WAIT:
			f->R.rax = process_wait(syscall_args[0]);
			break;
		
		case SYS_CREATE:
			f->R.rax = syscall_create(syscall_args[0], syscall_args[1]);
			break;
		
		case SYS_REMOVE:
			f->R.rax = syscall_remove(syscall_args[0]);
			break;
		
		case SYS_OPEN:
			f->R.rax = syscall_open(syscall_args[0]);
			break;
		
		case SYS_FILESIZE:
			f->R.rax = syscall_filesize(syscall_args[0]);
			break;
		
		case SYS_READ:
			//puts("CALL_READ");
			f->R.rax = syscall_read(syscall_args[0], syscall_args[1], syscall_args[2]);
			break;
		
		case SYS_WRITE:
			f->R.rax = syscall_write(syscall_args[0], (const void*)syscall_args[1], syscall_args[2]);
			break;
		
		case SYS_SEEK:
			syscall_seek(syscall_args[0], syscall_args[1]);
			break;
		case SYS_TELL:
			f->R.rax = syscall_tell(syscall_args[0]);
			break;
		
		case SYS_CLOSE:
			syscall_close(syscall_args[0]);
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