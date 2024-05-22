/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "vm/file.h"

/** Project 3-Memory Mapped Files */
#include "threads/mmu.h"
#include <string.h>

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

void vm_file_init(void)
{
}

bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;

	/** Project 3-Memory Mapped Files */
	struct vm_load_arg *arg = page->uninit.aux;
	file_page->file = arg->file;
	file_page->offset = arg->ofs;
	file_page->read_bytes = arg->read_bytes;
	file_page->remain_pages = arg->zero_bytes;
	return true;
}

static bool
file_backed_swap_in(struct page *page, void *kva)
{
	struct file_page *file_page = &page->file;
	/** Project 3-Memory Mapped Files */
	int read = file_read_at(file_page->file, page->frame->kva, file_page->read_bytes, file_page->offset);
	memset(page->frame->kva + read, 0, PGSIZE - read);
	return true;
}

static bool
file_backed_swap_out(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;
}

static void
file_backed_destroy(struct page *page)
{

	struct file_page *file_page UNUSED = &page->file;

	/** Project 3-Memory Mapped Files */
	struct thread *curr = thread_current();
	struct frame *frame = page->frame;

	if (pml4_is_dirty(curr->pml4, page->va))
	{
		file_write_at(file_page->file, frame->kva, file_page->read_bytes, file_page->offset);
		pml4_set_dirty(curr->pml4, page->va, false);
	}
	pml4_clear_page(curr->pml4, page->va);
}

void *
do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset)
{
	/** Project 3-Memory Mapped Files */
	struct file *file_ = file_reopen(file);
	void *addr_ = addr;
	unsigned remain_pages = (unsigned)pg_round_up(length) / PGSIZE;
	while (length > 0)
	{
		remain_pages -= 1;
		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;

		struct vm_load_arg *con = (struct vm_load_arg *)malloc(sizeof(struct vm_load_arg));
		con->file = file_;
		con->ofs = offset;
		con->read_bytes = page_read_bytes;
		con->zero_bytes = remain_pages;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr_,
											writable, file_backed_swap_in, con))
			return false;
		length -= page_read_bytes;
		addr_ += PGSIZE;

		offset += page_read_bytes;
	}
	return addr;
}

void do_munmap(void *addr)
{
	/** Project 3-Memory Mapped Files */
	struct thread *curr = thread_current();
	struct page *page = spt_find_page(&curr->spt, addr);

	while (page)
	{
		struct page *next = NULL;
		if (page->file.remain_pages > 0)
			next = spt_find_page(&curr->spt, page->va + PGSIZE);
		spt_remove_page(&curr->spt, page);
		page = next;
	}
}