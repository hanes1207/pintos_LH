#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
#include "threads/vaddr.h"
#include "devices/disk.h"

struct page;
enum vm_type;

#define SWAP_DISK_BLOCK_SECTORS (PGSIZE / DISK_SECTOR_SIZE)
struct swap_disk_block{
	disk_sector_t sectors[SWAP_DISK_BLOCK_SECTORS];
	struct list_elem elem;
};
struct anon_page {
    struct swap_disk_block* sdblk;
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
