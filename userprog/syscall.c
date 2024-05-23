#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/** project2-System Call */
#include "threads/mmu.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "userprog/process.h"

/** project3-Memory Mapped Files */
#include "vm/vm.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/** project2-System Call */
struct lock filesys_lock; // 파일 읽기/쓰기 용 lock

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

void syscall_init(void)
{
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    /** project2-System Call */
    // read & write 용 lock 초기화
    lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
    // TODO: Your implementation goes here.
    /** project2-System Call */
    int sys_number = f->R.rax;
#ifdef VM
    thread_current()->rsp = f->rsp;
#endif
    // Argument 순서
    // %rdi %rsi %rdx %r10 %r8 %r9

    switch (sys_number)
    {
    case SYS_HALT:
        halt();
        break;
    case SYS_EXIT:
        exit(f->R.rdi);
        break;
    case SYS_FORK:
        f->R.rax = fork(f->R.rdi);
        break;
    case SYS_EXEC:
        f->R.rax = exec(f->R.rdi);
        break;
    case SYS_WAIT:
        f->R.rax = process_wait(f->R.rdi);
        break;
    case SYS_CREATE:
        f->R.rax = create(f->R.rdi, f->R.rsi);
        break;
    case SYS_REMOVE:
        f->R.rax = remove(f->R.rdi);
        break;
    case SYS_OPEN:
        f->R.rax = open(f->R.rdi);
        break;
    case SYS_FILESIZE:
        f->R.rax = filesize(f->R.rdi);
        break;
    case SYS_READ:
        /** Project 3-Memory Mapped Files */
        check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 1);
        f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_WRITE:
        /** Project 3-Memory Mapped Files */
        check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 0);
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    case SYS_SEEK:
        seek(f->R.rdi, f->R.rsi);
        break;
    case SYS_TELL:
        f->R.rax = tell(f->R.rdi);
        break;
    case SYS_CLOSE:
        close(f->R.rdi);
        break;
    case SYS_DUP2:
        f->R.rax = dup2(f->R.rdi, f->R.rsi);
        break;
    case SYS_MMAP:
        f->R.rax = mmap((void *)f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
        break;
    case SYS_MUNMAP:
        munmap(f->R.rdi);
        break;
    default:
        exit(-1);
    }
}
/** Project 3-Memory Mapped Files */
void check_valid_buffer(void *buffer, unsigned size, void *rsp, bool to_write)
{
    for (int i = 0; i < size; i += 10)
    {
        struct page *page = check_address(buffer + i);
        if (page == NULL)
            exit(-1);
        if (to_write == true && page->writable == false)
            exit(-1);
    }
}

struct page *check_address(void *addr)
{
    if (is_kernel_vaddr(addr) || addr == NULL)
        exit(-1);
    struct page *page = spt_find_page(&thread_current()->spt, addr);
    if (!page)
        exit(-1);
    return page;
}

void halt(void)
{
    power_off();
}

void exit(int status)
{
    struct thread *t = thread_current();
    t->exit_status = status;
    // if (status < 0)
    //     PANIC("exit -1");
    printf("%s: exit(%d)\n", t->name, t->exit_status); // Process Termination Message
    thread_exit();
}

pid_t fork(const char *thread_name)
{
    check_address(thread_name);

    return process_fork(thread_name, NULL);
}

int exec(const char *cmd_line)
{
    check_address(cmd_line);

    off_t size = strlen(cmd_line) + 1;
    char *cmd_copy = palloc_get_page(PAL_ZERO);

    if (cmd_copy == NULL)
        return -1;

    memcpy(cmd_copy, cmd_line, size);

    if (process_exec(cmd_copy) == -1)
        exit(-1);

    NOT_REACHED();
    return 0; // process_exec 성공시 리턴 값 없음 (do_iret)
}

int wait(pid_t tid)
{
    return process_wait(tid);
}

bool create(const char *file, unsigned initial_size)
{
    check_address(file);
    lock_acquire(&filesys_lock); /** Project 3-Memory Mapped Files */
    bool succ = filesys_create(file, initial_size);
    lock_release(&filesys_lock); /** Project 3-Memory Mapped Files */

    return succ;
}

bool remove(const char *file)
{
    check_address(file);
    lock_acquire(&filesys_lock); /** Project 3-Memory Mapped Files */
    bool succ = filesys_remove(file);
    lock_release(&filesys_lock); /** Project 3-Memory Mapped Files */
    return succ;
}

int open(const char *file)
{
    check_address(file);
    lock_acquire(&filesys_lock); /** Project 3-Memory Mapped Files */
    struct file *newfile = filesys_open(file);

    int fd = -1;
    if (newfile == NULL)
        goto error;
    fd = process_add_file(newfile);

    if (fd == -1)
    {
        file_close(newfile);
    }
error:
    lock_release(&filesys_lock); /** Project 3-Memory Mapped Files */
    return fd;
}

int filesize(int fd)
{
    struct file *file = process_get_file(fd);

    if (file == NULL)
        return -1;

    return file_length(file);
}

/** Project 2-Extend File Descriptor */
int read(int fd, void *buffer, unsigned length)
{
    check_address(buffer);

/** #project3-Stack Growth */
#ifdef VM
    struct page *page = spt_find_page(&thread_current()->spt, buffer);
    if (page && !page->writable)
        exit(-1);
#endif

    struct thread *curr = thread_current();

    struct file *file = process_get_file(fd);

    if (file == STDIN)
    {
        int i = 0;
        char c;
        unsigned char *buf = buffer;

        for (; i < length; i++)
        {
            c = input_getc();
            *buf++ = c;
            if (c == '\0')
                break;
        }
        return i;
    }

    if (file == NULL || file == STDOUT || file == STDERR) // 빈 파일, stdout, stderr를 읽으려고 할 경우
        return -1;

    off_t bytes = -1;

    lock_acquire(&filesys_lock);
    bytes = file_read(file, buffer, length);
    lock_release(&filesys_lock);

    return bytes;
}

/** Project 2-Extend File Descriptor */
int write(int fd, const void *buffer, unsigned length)
{
    check_address(buffer);

    struct thread *curr = thread_current();
    off_t bytes = -1;

    struct file *file = process_get_file(fd);

    if (file == STDIN || file == NULL)
        return -1;

    if (file == STDOUT)
    {

        putbuf(buffer, length);
        return length;
    }

    if (file == STDERR)
    {

        putbuf(buffer, length);
        return length;
    }

    lock_acquire(&filesys_lock);
    bytes = file_write(file, buffer, length);
    lock_release(&filesys_lock);

    return bytes;
}

void seek(int fd, unsigned position)
{

    struct file *file = process_get_file(fd);

    if (file == NULL || (file >= STDIN && file <= STDERR))
        return;
    lock_acquire(&filesys_lock); /** Project 3-Memory Mapped Files */
    file_seek(file, position);
    lock_release(&filesys_lock); /** Project 3-Memory Mapped Files */
}

int tell(int fd)
{
    struct file *file = process_get_file(fd);

    if (file == NULL || (file >= STDIN && file <= STDERR))
        return -1;
    lock_acquire(&filesys_lock); /** Project 3-Memory Mapped Files */
    int res = file_tell(file);
    lock_release(&filesys_lock); /** Project 3-Memory Mapped Files */
    return res;
}

/** Project 2-Extend File Descriptor */
void close(int fd)
{
    struct thread *curr = thread_current();
    struct file *file = process_get_file(fd);

    if (file == NULL)
        return;

    process_close_file(fd);

    if (file <= STDERR)
    {
        goto done;
    }

    if (file->dup_count == 0)
    {
        lock_acquire(&filesys_lock); /** Project 3-Memory Mapped Files */
        file_close(file);
        lock_release(&filesys_lock); /** Project 3-Memory Mapped Files */
    }

    else
        file->dup_count--;

done:

    return;
}

/** Project 2-Extend File Descriptor */
int dup2(int oldfd, int newfd)
{
    if (oldfd < 0 || newfd < 0)
        return -1;

    struct file *oldfile = process_get_file(oldfd);

    if (oldfile == NULL)
        return -1;

    if (oldfd == newfd)
        return newfd;

    struct file *newfile = process_get_file(newfd);

    if (oldfile == newfile)
        return newfd;

    close(newfd);

    newfd = process_insert_file(newfd, oldfile);

    return newfd;
}

/** Project 3-Memory Mapped Files */
void *mmap(void *addr, size_t length, int writable, int fd, off_t offset)
{
    // CASE 1. `addr` 가 0인 경우
    if (addr == NULL)
        goto error;
    // CASE 2. `addr` 가 커널 가상 주소인 경우
    if (is_kernel_vaddr(addr))
        goto error;
    // CASE 3. `addr`나 `offset`가 page-aligned 되지 않은 경우
    if (pg_ofs(addr) || pg_ofs(offset))
        goto error;
    // CASE 6. 읽으려는 파일의 길이가 0보다 작거나 같은 경우
    if (length <= 0)
        goto exit;
    // CASE 5. 읽으려는 파일의 offset 위치가 PGSIZE 보다 큰 경우
    if (offset > PGSIZE)
        goto error;
    // CASE 4. 기존에 매핑된 페이지 집합(stack, 페이지)과 겹치는 경우
    void *_addr = addr;
    size_t _length = length;
    while (_length > 0)
    {
        size_t _b = _length > PGSIZE ? PGSIZE : _length;
        if (is_kernel_vaddr(_addr))
            goto error;
        if (spt_find_page(&thread_current()->spt, _addr))
            goto error;
        _addr += _b;
        _length -= _b;
    }
    // CASE 7. STDIN, STDOUT, STDERR 인 경우
    // CASE 8. 파일 객체가 존재하지 않는 경우
    struct file *file = process_get_file(fd);
    if (file <= STDERR)
        goto error;
    // CASE 9. fd로 열린 파일의 길이가 0인 경우
    if (file_length(file) == 0)
        goto error;

    lock_acquire(&filesys_lock); /** Project 3-Memory Mapped Files */
    void *res = do_mmap(addr, length, writable, file, offset);
    lock_release(&filesys_lock); /** Project 3-Memory Mapped Files */

    return res;

error:
    // NOT_REACHED();
    return NULL;
exit:
    exit(-1);
}

void munmap(void *addr)
{
    if (!addr || is_kernel_vaddr(addr) || pg_ofs(addr))
    {
        return;
    }
    lock_acquire(&filesys_lock); /** Project 3-Memory Mapped Files */
    do_munmap(addr);
    lock_release(&filesys_lock); /** Project 3-Memory Mapped Files */
}