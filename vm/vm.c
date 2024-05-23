#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/** #project3-Memory management */
#include <hash.h>
#include "threads/thread.h"
#include "threads/mmu.h"
struct list frame_table;
struct list_elem *next = NULL;

/** Project 3-Swap In/Out */
struct lock frame_lock;

void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();

	list_init(&frame_table);

	/** Project 3-Swap In/Out */
	lock_init(&frame_lock);
}

enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/** #project3-Anonymous Page */
static void hash_page_destroy(struct hash_elem *e, void *aux);

bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)
	struct supplemental_page_table *spt = &thread_current()->spt;
	// printf("할당할께~~ %p\n", upage);
	/* Check wheter the upage is already occupied or not. */
	struct page *page = spt_find_page(spt, upage);
	if (page == NULL)
	{
		/** #project3-Anonymous Page */
		page = malloc(sizeof(struct page));
		if (!page)
			goto err;
		bool (*initializer)(struct page *, enum vm_type, void *);
		initializer = NULL;

		switch (VM_TYPE(type))
		{
		case VM_ANON:
			initializer = anon_initializer;
			break;
		case VM_FILE:
			initializer = file_backed_initializer;
			break;
		}
		uninit_new(page, upage, init, type, aux, initializer);
		page->writable = writable;
		page->pml4 = thread_current()->pml4; /** Project 3-Swap In/Out */
		return spt_insert_page(&thread_current()->spt, page);
	}
err:

	return false;
}

struct page *
spt_find_page(struct supplemental_page_table *spt, void *va)
{
	struct page *page = (struct page *)malloc(sizeof(struct page));
	page->va = pg_round_down(va);
	struct hash_elem *e = hash_find(&spt->hash_table, &page->hash_elem);
	free(page);

	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

bool spt_insert_page(struct supplemental_page_table *spt,
					 struct page *page)
{
	/** #project3-Memory management */
	return !hash_insert(spt, &page->hash_elem);
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	hash_delete(&spt->hash_table, &page->hash_elem);
	vm_dealloc_page(page);
	return true;
}

static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/** Project 3-Swap In/Out */
	for (next = list_begin(&frame_table); next != list_end(&frame_table); next = list_next(next))
	{
		victim = list_entry(next, struct frame, frame_elem);
		if (pml4_is_accessed(thread_current()->pml4, victim->page->va))
			pml4_set_accessed(thread_current()->pml4, victim->page->va, false);
		else
			return victim;
	}
	return victim;
}

static struct frame *
vm_evict_frame(void)
{
	struct frame *victim = vm_get_victim();
	/** Project 3-Swap In/Out */
	if (victim->page)
		swap_out(victim->page);
	return victim;
}

static struct frame *
vm_get_frame(void)
{
	/** #project3-Memory management */
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
	ASSERT(frame != NULL);

	// if (!frame)
	// 	PANIC("todo");

	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
	if (!frame->kva)
	{
		/** Project 3-Swap In/Out */
		free(frame);
		frame = vm_evict_frame();
		frame->page = NULL;

		return frame;
	}
	lock_acquire(&frame_lock);
	list_push_back(&frame_table, &frame->frame_elem);
	lock_release(&frame_lock);
	frame->page = NULL;
	// ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

static void
vm_stack_growth(void *addr)
{
	// /** #project3-Stack Growth */
	vm_alloc_page(VM_ANON, pg_round_down(addr), 1);
}

static bool
vm_handle_wp(struct page *page UNUSED)
{
}

bool vm_try_handle_fault(struct intr_frame *f, void *addr,
						 bool user, bool write, bool not_present)
{
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = NULL;
	void *rsp;
	/** #project3-Anonymous Page */

	if (addr == NULL || is_kernel_vaddr(addr) || !not_present)
		return false;
	/** #project3-Stack Growth */
	if (user)
		rsp = f->rsp;
	else
		rsp = thread_current()->rsp;

	page = spt_find_page(spt, addr);

	// printf("쉿! 폴트중~ addr: %p , rsp : %p 읽기 : %d\n", addr, rsp, write);
	/** #project3-Memory management */
	if (USER_STACK_MIN <= rsp - 8 && rsp - 8 == addr && addr <= USER_STACK)
		vm_stack_growth(addr);
	else if (USER_STACK_MIN <= rsp && rsp <= addr && addr <= USER_STACK)
		vm_stack_growth(addr);

	page = spt_find_page(spt, addr);

	if (!page || (write && !page->writable))
		return false;
	return vm_do_claim_page(page);
}

void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

bool vm_claim_page(void *va)
{
	struct page *page = NULL;

	/** #project3-Memory management */
	if (page = spt_find_page(&thread_current()->spt, va))
		return vm_do_claim_page(page);
	else
		return false;
}

static bool
vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/** #project3-Memory management */
	if (!pml4_set_page(page->pml4, page->va, frame->kva, page->writable)) /** Project 3-Swap In/Out */
		return false;
	// printf("kva : %p\n", frame->kva);
	return swap_in(page, frame->kva);
}
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	/** #project3-Memory management */
	hash_init(&spt->hash_table, page_hash, page_less, NULL);
}

bool supplemental_page_table_copy(struct supplemental_page_table *dst,
								  struct supplemental_page_table *src)
{
	/** #project3-Anonymous Page */
	struct hash_iterator i;
	hash_first(&i, &src->hash_table);
	while (hash_next(&i))
	{

		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		enum vm_type src_type = src_page->operations->type;
		if (src_type == VM_UNINIT)
		{
			vm_alloc_page_with_initializer(
				src_page->uninit.type,
				src_page->va,
				src_page->writable,
				src_page->uninit.init,
				src_page->uninit.aux);
		}
		else if (src_type == VM_FILE)
		{

			if (vm_alloc_page(src_type, src_page->va, src_page->writable))
			{
				struct page *dst_page = spt_find_page(dst, src_page->va);

				/** Project 3-Memory Mapped Files */
				dst_page->frame = src_page->frame;
				dst_page->operations = src_page->operations;
				dst_page->file.file = file_reopen(src_page->file.file);
				dst_page->file.offset = src_page->file.offset;
				dst_page->file.read_bytes = src_page->file.read_bytes;
				dst_page->file.remain_pages = src_page->file.remain_pages;
				pml4_set_page(thread_current()->pml4, dst_page->va, src_page->frame->kva, src_page->writable); /** Project 3-Swap In/Out */
			}
		}
		else
		{
			if (vm_alloc_page(src_type, src_page->va, src_page->writable) && vm_claim_page(src_page->va))
			{
				struct page *dst_page = spt_find_page(dst, src_page->va);
				memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
			}
		}
	}
	return true;
error:
	return false;
}

void supplemental_page_table_kill(struct supplemental_page_table *spt)
{
	/** #project3-Anonymous Page */
	hash_clear(&spt->hash_table, hash_page_destroy);
}

/** #project3-Memory management */
uint64_t page_hash(const struct hash_elem *e, void *aux)
{
	struct page *page = hash_entry(e, struct page, hash_elem);
	return hash_bytes(&page->va, sizeof *page->va);
}

bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
	struct page *page_a = hash_entry(a, struct page, hash_elem);
	struct page *page_b = hash_entry(b, struct page, hash_elem);

	return page_a->va < page_b->va;
}

/** #project3-Anonymous Page */
static void hash_page_destroy(struct hash_elem *e, void *aux)
{
	struct page *page = hash_entry(e, struct page, hash_elem);
	destroy(page);
	free(page);
}
void clear_frame(struct page *page)
{
	lock_acquire(&frame_lock);
	list_remove(&page->frame->frame_elem);
	lock_release(&frame_lock);
	page->frame->page = NULL;
	page->frame = NULL;
	free(page->frame);
}