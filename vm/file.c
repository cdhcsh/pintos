/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

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
}
/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset)
{
	/** Project 3-Memory Mapped Files */
	struct file *file_ = file_duplicate(file);
	while (length > 0)
	{
		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE - length;

		struct file_arg *file_arg = (struct file_arg *)malloc(sizeof(struct file_arg));
		file_arg->file = file;
		file_arg->ofs = offset;
		file_arg->read_bytes = page_read_bytes;
		file_arg->zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
											writable, file_lazy_load, file_arg))
			return false;

		length -= page_read_bytes;
		addr += PGSIZE;

		offset += page_read_bytes;
	}
	return true;
}

bool file_lazy_load(struct page *page, void *aux)
{
	// 파일 로드해서 물리메모리에 적재함
	struct file_arg *con = aux;
	if (file_read_at(con->file, page->frame->kva, con->read_bytes, con->ofs) != con->read_bytes)
	{
		return false;
	}
	memset(page->frame->kva + con->read_bytes, 0, con->zero_bytes);
	return true;
}

/* Do the munmap */
void do_munmap(void *addr)
{
}