#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

bool process_create_file(struct thread* target, const char* file, unsigned initial_size);
bool process_remove_file(struct thread* target, const char* file);
int process_open_file(struct thread* target, const char* file);
int process_filesize(struct thread* target, int fd);
int process_read(struct thread* target, int fd, void* buffer, unsigned size);
int process_write(struct thread* target, int fd, const void* buffer, unsigned size);
void process_seek(struct thread* target, int fd, unsigned position);
unsigned process_tell(struct thread* target, int fd);
void process_close(struct thread* target, int fd);

#endif /* userprog/process.h */
