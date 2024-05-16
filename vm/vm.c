/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/** #project3-Memory management */
#include <hash.h>
#include "threads/thread.h"
#include "threads/mmu.h"
struct list frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
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

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/** #project3-Anonymous Page */
static void hash_page_destroy(struct hash_elem *e, void *aux);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: 페이지를 생성하고, VM 유형에 따라 초기화자를 가져온 다음,
		 * uninit_new를 호출하여 "uninit" 페이지 구조체를 생성하세요.
		 * uninit_new를 호출한 후에 필드를 수정해야 합니다. */
		/* TODO: 페이지를 spt에 삽입하세요. */

		/** #project3-Anonymous Page */
		struct page *page = malloc(sizeof(struct page));
		if (!page)
			goto err;
		bool (*initializer)(struct page *, enum vm_type, void *);

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
		return spt_insert_page(&thread_current()->spt, page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt, void *va)
{
	struct page *page = NULL;
	/** #project3-Memory management */
	struct page _;
	struct hash_elem *e;
	_.va = pg_round_down(va);
	return (e = hash_find(spt, &_.hash_elem)) ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt,
					 struct page *page)
{
	/** #project3-Memory management */
	return !hash_insert(spt, &page->hash_elem);
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
	/** #project3-Memory management */
	struct frame *frame = calloc(1, sizeof *frame);
	if (!frame)
		PANIC("todo");

	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
	if (!frame->kva)
		PANIC("todo");

	list_push_back(&frame_table, &frame->frame_elem);
	frame->page = NULL;
	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr)
{
	/** #project3-Stack Growth */
	bool succ;
	addr = pg_round_down(addr);
	uint64_t stack_bottom = thread_current()->stack_bottom;

	while (stack_bottom > USER_STACK_MIN && stack_bottom > addr)
	{
		stack_bottom -= PGSIZE;
		if (vm_alloc_page(VM_ANON, stack_bottom, 1))
			succ = vm_claim_page(stack_bottom);
		if (!succ)
			PANIC("todo - stack grows");
	}
	thread_current()->stack_bottom = stack_bottom;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr,
						 bool user, bool write, bool not_present)
{
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = NULL;

	/** #project3-Anonymous Page */
	if (addr == NULL || is_kernel_vaddr(addr))
		return false;

	/** #project3-Stack Growth */
	if (addr >= USER_STACK_MIN)
	{
		if (addr != f->rsp)
			return false;
		vm_stack_growth(addr);
		return true;
	}
	return (page = spt_find_page(spt, addr)) ? vm_do_claim_page(page) : false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va)
{
	struct page *page = NULL;

	/** #project3-Memory management */
	if (page = spt_find_page(&thread_current()->spt, va))
		return vm_do_claim_page(page);
	else
		return false;
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	struct thread *cur = thread_current();

	/** #project3-Memory management */
	pml4_set_page(cur->pml4, page->va, frame->kva, page->writable);

	return swap_in(page, frame->kva);
}
/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	/** #project3-Memory management */
	hash_init(&spt->hash_table, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
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
	supplemental_page_table_kill(dst);
	return false;
}

/* Free the resource hold by the supplemental page table */
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

	if (page->frame)
		free(page->frame);
	// destroy(page);
	free(page);
}