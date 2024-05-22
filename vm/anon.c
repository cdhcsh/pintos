#include "vm/vm.h"
#include "devices/disk.h"

static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/** Project 3-Swap In/Out */
#include <bitmap.h>
#include "threads/mmu.h">
static struct bitmap *swap_bitmap;
static struct lock swap_lock;

void vm_anon_init(void)
{
	/** Project 3-Swap In/Out */
	swap_disk = disk_get(1, 1);
	swap_bitmap = bitmap_create(disk_size(swap_disk) / SECTOR_PER_PAGE);
	lock_init(&swap_lock);
}

bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
	struct uninit_page *uninit = &page->uninit;
	memset(uninit, 0, sizeof(struct uninit_page));
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->page_no = BITMAP_ERROR;
	return true;
}

static bool
anon_swap_in(struct page *page, void *kva)
{
	struct anon_page *anon_page = &page->anon;
	/** Project 3-Swap In/Out */
	lock_acquire(&swap_lock);
	if (anon_page->page_no == BITMAP_ERROR)
		return false;

	if (!bitmap_test(swap_bitmap, anon_page->page_no))
		return false;

	bitmap_set(swap_bitmap, anon_page->page_no, false);

	for (size_t i = 0; i < SECTOR_PER_PAGE; i++)
		disk_read(swap_disk, (anon_page->page_no * SECTOR_PER_PAGE) + i, kva + (i * DISK_SECTOR_SIZE));

	anon_page->page_no = BITMAP_ERROR;
	lock_release(&swap_lock);

	return true;
}

static bool
anon_swap_out(struct page *page)
{
	struct anon_page *anon_page = &page->anon;
	/** Project 3-Swap In/Out */
	lock_acquire(&swap_lock);
	size_t page_no = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);

	if (page_no == BITMAP_ERROR)
		return false;

	for (size_t i = 0; i < SECTOR_PER_PAGE; i++)
		disk_write(swap_disk, (page_no * SECTOR_PER_PAGE) + i, page->va + (i * DISK_SECTOR_SIZE));
	anon_page->page_no = page_no;
	page->frame->page = NULL;
	page->frame = NULL;
	pml4_clear_page(thread_current()->pml4, page->va);
	lock_release(&swap_lock);
}

static void
anon_destroy(struct page *page)
{
	struct anon_page *anon_page = &page->anon;
	/** Project 3-Swap In/Out */
	if (anon_page->page_no != BITMAP_ERROR)
	{
		lock_acquire(&swap_lock);
		bitmap_set(swap_bitmap, anon_page->page_no, false);
		lock_release(&swap_lock);
	}

	if (page->frame)
	{
		list_remove(&page->frame->frame_elem);
		page->frame->page = NULL;
		free(page->frame);
		page->frame = NULL;
	}
}
