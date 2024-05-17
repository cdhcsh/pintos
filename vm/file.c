/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "vm/file.h"

/** Project 3-Memory Mapped Files */
#include "threads/mmu.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void)
{
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in(struct page *page, void *kva)
{
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy(struct page *page)
{

	struct file_page *file_page UNUSED = &page->file;
	struct thread *curr = thread_current();

	struct vm_load_arg *con = page->uninit.aux;
	struct frame *frame = page->frame;

	if (pml4_is_dirty(curr->pml4, page->va))
	{
		file_write_at(con->file, frame->kva, con->read_bytes, con->ofs);
		pml4_set_dirty(curr->pml4, page->va, false);
	}
	pml4_clear_page(curr->pml4, page->va);
}
/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset)
{
	/** Project 3-Memory Mapped Files */
	struct file *file_ = file_duplicate(file);
	void *addr_ = addr;
	while (length > 0)
	{
		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE - length;

		struct vm_load_arg *con = (struct vm_load_arg *)malloc(sizeof(struct vm_load_arg));
		con->file = file_;
		con->ofs = offset;
		con->read_bytes = page_read_bytes;
		con->zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr_,
											writable, file_lazy_load, con))
			return false;

		length -= page_read_bytes;
		addr_ += PGSIZE;

		offset += page_read_bytes;
	}
	return addr;
}

/** Project 3-Memory Mapped Files */
bool file_lazy_load(struct page *page, void *aux)
{
	// 파일 로드해서 물리메모리에 적재함
	struct vm_load_arg *con = aux;
	int read = file_read_at(con->file, page->frame->kva, con->read_bytes, con->ofs);
	return true;
}

/* Do the munmap */
void do_munmap(void *addr)
{
	/** Project 3-Memory Mapped Files */
	struct thread *curr = thread_current();
	struct page *page = spt_find_page(&curr->spt, addr);
	struct file *file = ((struct vm_load_arg *)page->uninit.aux)->file;
	while (page)
	{
		if (!page->uninit.aux || ((struct vm_load_arg *)page->uninit.aux)->file != file)
		{
			break;
		}
		spt_remove_page(&curr->spt, page);
		addr += PGSIZE;
		page = spt_find_page(&curr->spt, addr);
	}
	file_close(file);
}