#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);


// Loads a new thread that runs a user program from FILENAME. Before process execute() is returned, the new thread may get scheduled. If the thread is not created then returns error otherwise the thread id is returned.
tid_t process_execute (const char *file_name) 
{
  tid_t tid;
  char *fn_copy;
  // To prevent a race between load() and caller, we create a copy of filename 
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  // Creating a new thread that executes FILENAME 
  char *argv0, *save_ptr;
  argv0 = strtok_r(fn_copy, " ", &save_ptr);
  tid = thread_create (argv0, thread_current()->priority, start_process, save_ptr);

  // Makes the parent wait till the child process successfully loaded its executable. 
  sema_down(&thread_current()->process_wait);
  
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 

  return thread_current()->child_load_status;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  //   thread_current()->name, thread_current()->tid, thread_current()->priority);
  char * args = args_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (args, &if_.eip, &if_.esp);

  // Quit if the load fails

  palloc_free_page(pg_round_down(args));

  if (success == false) 
  {
    if (thread_current()->parent != NULL)
      thread_current()->parent->child_load_status = -1;
    thread_exit();
  }
   // The child thread starts waiting for its parent if loading succeeds
  sema_up(&thread_current()->parent->process_wait);
  sema_down(&thread_current()->process_wait);

  // Prevents the modification of the executatble of a running process 
  thread_current()->file = filesys_open (thread_name());
  file_deny_write(thread_current()->file);

  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

int process_wait (tid_t child_tid) 
{ 
  int status = -1;
  struct list_elem *e;
  struct thread *cur = thread_current();
  struct thread *child = NULL;
  for (e = list_begin (&cur->children); e != list_end (&cur->children); e = list_next (e))
  {
    struct thread *tmp = list_entry (e, struct thread, child_elem);
    if (tmp->tid == child_tid)
    {
      child = tmp;
      break;
    }
  }

  // Makes it wait for its child.
  if (child != NULL) {
    sema_up(&child->process_wait);
    sema_down(&cur->process_wait);   
    status = cur->child_exit_status;
  }
  return status;
}

// Frees the resources of the current process.
void process_exit (void)
{
  struct thread *cur = thread_current ();
  if (cur->parent != NULL)
  {
    list_remove(&cur->child_elem);
    sema_up(&cur->parent->process_wait);
  }

  struct list_elem *e;
  for (e = list_begin (&cur->children); e != list_end (&cur->children);
     e = list_next (e))
  {
    struct thread *tmp = list_entry (e, struct thread, child_elem);
    sema_up(&tmp->process_wait);
  }


  /* Destroying the current process's page directory alog wtih switching back
     to the kernel-only page directory. */
  uint32_t *pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Order here is crucial.   Set
         cur->pagedir to NULL before switching page directories,so that a timer interrupt can't switch back to the
         process page directory.  ACTIVATE the base pagedirectory before destroying the process's page
         directory, or our active page directory will be one that can be freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Setiing up the CPU for running user code in the current
   thread.This function is called on for every context switch. */
void
process_activate (void)
{
  struct thread *td = thread_current ();

  /* Activating thread's page tables. */
  pagedir_activate (td->pagedir);


  /* Setting  thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}



/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8 appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

#define PT_NULL    0            // Ignore. 
#define PT_LOAD    1            // Loadable segment. 
#define PT_DYNAMIC 2            // Dynamic linking info. 
#define PT_INTERP  3            // Name of dynamic loader. 
#define PT_NOTE    4            // Auxiliary info. 
#define PT_SHLIB   5            // Reserved. 
#define PT_PHDR    6            // Program header table. 
#define PT_STACK   0x6474e551   // Stack segment.

struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

#define PF_X 1          // Executable
#define PF_W 2          // Writable
#define PF_R 4          // Readable

static bool setup_stack (void **esp, const char *args);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *args, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  // Page directory is allocated and activated
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  // Executable file is opened
  const char *file_name = thread_name();
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load : %s :  open failed\n", file_name);
      goto done; 
    }

  // Executable header is read and verified
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof (struct Elf32_Phdr) || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  // Program headers are read
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }


  if (!setup_stack (esp, args))
    goto done;

  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
 done:

  file_close (file);
  return success;
}


static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      // Page is added to the process's address space.
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }
        read_bytes = read_bytes - page_read_bytes;
        zero_bytes = zero_bytes - page_zero_bytes;
        upage = upage + PGSIZE;
    }
  return true;
}

// Utilized in inserting argument address into list. 
struct argument_addr
{
  struct list_elem list_elem;
  uint32_t addr;
};


void push_argument_(void **esp, const char *arg, struct list *list) 
{
  int len = strlen(arg) + 1;
  *esp -= len;
  struct argument_addr *addr = malloc(sizeof(struct argument_addr));
  memcpy(*esp, arg, len);

  addr->addr = *esp;
 
  list_push_back(list, &addr->list_elem);
}


void push_arguments(void **esp, const char *args) 
{
  struct list list;
  list_init (&list);

  *esp = PHYS_BASE; 
  uint32_t arg_num = 1;

  // Pushes filename onto stack.
  const char *arg = thread_name();
  push_argument_(esp, arg, &list);

  // Pushes other arguments onto stack. 
  char *token, *save_ptr;
  for (token = strtok_r(args, " ", &save_ptr); 
    token != NULL;
    token = strtok_r(NULL, " ", &save_ptr))
  {
    arg_num += 1;
    push_argument_(esp, token, &list);
  }

  int total = PHYS_BASE - *esp;
  *esp = *esp - (4 - total % 4) - 4;

  *esp -= 4;

  * (uint32_t *) *esp = (uint32_t) NULL;

  /* Pushing  all the addresses of arguments into stack. 
     The addresses are popped out from list. */
  while (!list_empty(&list)) {
    struct argument_addr *addr = 
      list_entry(list_pop_back(&list), struct argument_addr, list_elem);
    *esp -= 4;
    * (uint32_t *) *esp = addr->addr;
    
  }

  
  *esp -= 4;
  * (uint32_t *) *esp = (uint32_t *)(*esp + 4);

  
  *esp -= 4;
  * (uint32_t *) *esp = arg_num;

  /* Push 0 as a fake return address. */
  *esp -= 4;
  * (uint32_t *) *esp = 0x0;

  
}

/* Create a minimal stack mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char *args) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) 
      {
        *esp = PHYS_BASE;

        
        push_arguments(esp, args);
        
      }
        
      else
        palloc_free_page (kpage);
    }
  return success;
}


/* Adding a mapping from user virtual address upage to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page; otherwise, it is read-only. Upage must not already be mapped.
   Kpage should probably be a page obtained from the user pool
   with palloc_get_page().
   Return false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
