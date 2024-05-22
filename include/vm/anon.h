#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
struct page;
enum vm_type;

struct anon_page
{
    /** Project 3-Swap In/Out */
    size_t page_no;
};

/** Project 3-Swap In/Out */
#include "devices/disk.h"
#define SECTOR_PER_PAGE (PGSIZE / DISK_SECTOR_SIZE)

void vm_anon_init(void);
bool anon_initializer(struct page *page, enum vm_type type, void *kva);

#endif