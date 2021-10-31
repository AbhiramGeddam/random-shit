#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/block.h"

typedef int pid_t;

struct file_descriptor
{
  int fd;
  struct file *file;
  struct list_elem elem;
};

static struct lock filesys_lock;

// helper function
bool is_valid_ptr(const void *ptr);
bool is_valid_filename(const void *file);

static void syscall_handler(struct intr_frame *);

static void halt(void);

static pid_t exec(const char *cmd_line);
static int wait(pid_t pid);

static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);

static int open(const char *file);
static void close(int fd);

static filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, const void *buffer, unsigned size);

static void seek(int fd, unsigned position);
static unsigned tell(int fd);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler(struct intr_frame *f)
{
  uint32_t *esp = f->esp;
  uint32_t *argv0 = esp + 1;
  uint32_t *argv1 = esp + 2;
  uint32_t *argv2 = esp + 3;

  if (!is_valid_ptr(esp) || !is_valid_ptr(argv0) || !is_valid_ptr(argv1) || !is_valid_ptr(argv2))
  {
    exit(-1);
  }

  uint32_t syscall_num = *esp;

  if (syscall_num == 0) 
  {
    // SYS_HALT
    halt();
  }
  else if (syscall_num == 1)
  {
    // SYS_EXIT
    exit(*argv0);
  }
  else if (syscall_num == 2)
  {
    // SYS_EXEC
    f->eax = exec((char *)*argv0);
  }
  else if (syscall_num == 3)
  {
    // SYS_WAIT
    f->eax = wait(*argv0);
  }
  else if (syscall_num == 4)
  {
    // SYS_CREATE
    f->eax = create((char *)*argv0, *argv1);
  }
  else if (syscall_num == 5)
  {
    // SYS_REMOVE
    f->eax = remove((char *)*argv0);
  }
  else if (syscall_num == 6)
  {
    // SYS_OPEN
    f->eax = open((char *)*argv0);
  }
  else if (syscall_num == 7)
  {
    // SYS_FILESIZE
    f->eax = filesize(*argv0);
  }
  else if (syscall_num == 8)
  {
    // SYS_READ
    f->eax = read(*argv0, (void *)*argv1, *argv2);
  }
  else if (syscall_num == 9)
  {
    // SYS_WRITE
    f->eax = write(*argv0, (void *)*argv1, *argv2);
  }
  else if (syscall_num == 10)
  {
    // SYS_SEEK
    seek(*argv0, *argv1);
  }
  else if (syscall_num == 11)
  {
    // SYS_TELL
    f->eax = tell(*argv0);
  }
  else if (syscall_num == 12)
  {
    // SYS_CLOSE
    close(*argv0);
  }
}

// terminates the OS
static void halt(void)
{
  shutdown_power_off();
}

bool is_valid_ptr(const void *ptr)
{
  // The pointer should not be a null pointer
  if (ptr == NULL) 
  {
    return false;
  }
  // The pointer should point to memory in user virtual address space
  if (!is_user_vaddr(ptr))
  {
    return false;
  }
  // The pointer should not point to unmapped virtual memory
  if (pagedir_get_page(thread_current()->pagedir, ptr) == NULL)
  {
    return false;
  }
  return true;
}

// To check if the file has a filename that is valid
bool is_valid_filename(const void *file)
{
  if (is_valid_ptr(file) == false)
    exit(-1);

  int len = strlen(file);
  // length of filename should be between 1 and 14
  if (len >= 1 && len <= 14)
  {
    return true;
  }
  return false;
}

struct file_descriptor *get_openfile(int f_d)
{
  struct list_elem *e;
  struct list *list = &thread_current()->open_fd;
  for (e = list_begin(list); e != list_end(list); e = list_next(e))
  {
    struct file_descriptor *f = list_entry(e, struct file_descriptor, elem);
    if (f->fd == f_d)
      return f;
    else if (f->fd > f_d)
      return NULL;
  }
  return NULL;
}


void close_openfile(int f_d)
{
  struct list_elem *e;
  struct list *list = &thread_current()->open_fd;
  for (e = list_begin(list); e != list_end(list); e = list_next(e))
  {
    struct file_descriptor *f =
        list_entry(e, struct file_descriptor, elem);
    if (f->fd == f_d)
    {
      list_remove(e);
      file_close(f->file);
      free(f);
      return;
    }
    else if (f->fd > f_d)
      return;
  }
  return;
}


// Returns the status to kernel and terminates the user program. If the status is 0, success, otherwise failure
void exit(int status)
{
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
  // If its parent is still waiting for it, tell its parent its exit status
  if (cur->parent != NULL){
    cur->parent->child_exit_status = status;
  }

  /* Close all the files the process has opened. */
  while (!list_empty(&cur->open_fd))
  {
    close(list_entry(list_begin(&cur->open_fd), struct file_descriptor, elem)->fd);
  }

  // Closing its executable file.
  file_close(cur->file);

  thread_exit();
}

// Run the executable whose name is given in cmd_line along with the passed arguments. Return the new process's program id. Should return pid = -1, or else should not be a valid pid, in case the program cannot load or run for any reason.
static pid_t exec(const char *cmd_line)
{
  if (is_valid_ptr(cmd_line) == false)
    exit(-1);

  lock_acquire(&filesys_lock);
  tid_t tid = process_execute(cmd_line);
  lock_release(&filesys_lock);

  return tid;
}



// Wait until child process terminates (if alive). Returns the exit status of the child.
static int wait(pid_t process_id)
{
  return process_wait(process_id);
}

// Creating a new file called *file that has intial_size equal to size. Returns true for success and false for failure to create file.
static bool create(const char *file, unsigned initial_size)
{
  block_sector_t inode_sector = 0;
  struct dir *dir = dir_open_root();
  if (!is_valid_filename(file))
    return false;

  lock_acquire(&filesys_lock);

  bool success = false;
  if (dir != NULL){
    if (free_map_allocate(1, &inode_sector)){
      if (inode_create(inode_sector, initial_size)){
        if (dir_add(dir, file, inode_sector)){
          success = true;
        }
      }
    }
  }

    if (success == false && inode_sector != 0)
      free_map_release(inode_sector, 1);
  dir_close(dir);

  lock_release(&filesys_lock);

  return success;
}

// Delete the file called *file. Returns true for success and false for failure to remove file.
static bool remove(const char *file)
{
  if (is_valid_filename(file) == false)
    return false;

  bool status;

  lock_acquire(&filesys_lock);
  status = filesys_remove(file);
  lock_release(&filesys_lock);

  return status;
}

// Assign unique file descriptor to a file and return it.
 
int assign_fd()
{
  struct list *list = &thread_current()->open_fd;
  if (list_empty(list))
    return 2;
  else
  {
    struct file_descriptor *f = list_entry(list_back(list), struct file_descriptor, elem);
    int a = f->fd + 1;
    return a;
  }
}

// Compare file descriptor values as list_elem. Return true if fd(a) is less than fd(b), otherwise false. 
bool cmp_fd(const struct list_elem *a, const struct list_elem *b, void *aux)
{
  struct file_descriptor *left = list_entry(a, struct file_descriptor, elem);
  struct file_descriptor *right = list_entry(b, struct file_descriptor, elem);
  return left->fd < right->fd;
}

// Opens the file called *file and assign the opened file a file descriptor and the current process must keep track of it using open_fd list. Return file descriptor if the file can be opened, otherwise -1.
static int open(const char *file)
{
  int f_d = -1;

  if (is_valid_filename(file) == false)
    return f_d;

  lock_acquire(&filesys_lock);
  struct list *list = &thread_current()->open_fd;
  struct file *file_struct = filesys_open(file);
  if (file_struct != NULL)
  {
    struct file_descriptor *tmp = malloc(sizeof(struct file_descriptor));
    tmp->fd = assign_fd();
    tmp->file = file_struct;
    f_d = tmp->fd;
    list_insert_ordered(list, &tmp->elem, (list_less_func *)cmp_fd, NULL);
  }
  lock_release(&filesys_lock);
  return f_d;
}

static void close(int f_d)
{
  lock_acquire(&filesys_lock);
  close_openfile(f_d);
  lock_release(&filesys_lock);
}

// Returns the size of the file descriptor file.  
static int filesize(int f_d)
{
  int file_size = -1;
  lock_acquire(&filesys_lock);

  struct file_descriptor *file_descriptor = get_openfile(f_d);
  if (file_descriptor != NULL)
    file_size = file_length(file_descriptor->file);

  lock_release(&filesys_lock);
  return file_size;
}

static int read(int f_d, void *buffer, unsigned size)
{
  int status = -1;

  if (is_valid_ptr(buffer) == false || is_valid_ptr(buffer + size - 1) == false)
    exit(-1);

  lock_acquire(&filesys_lock);
  if (f_d == STDIN_FILENO) /* Fead from the keyboard.*/
  {
    uint8_t *p = buffer;
    uint8_t c;
    unsigned counter = 0;
    while (counter < size && (c = input_getc()) != 0)
    {
      *p = c;
      p++;
      counter++;
    }
    *p = 0;
    status = size - counter;
  }
  else if (f_d != STDOUT_FILENO)
  {
    struct file_descriptor *file_descriptor = get_openfile(f_d);
    if (file_descriptor != NULL)
      status = file_read(file_descriptor->file, buffer, size);
  }

  lock_release(&filesys_lock);

  return status;
}

static int
write(int f_d, const void *buffer, unsigned size)
{
  int status = 0;

  if (buffer == NULL || is_valid_ptr(buffer) == false || is_valid_ptr(buffer + size - 1) == false)
    exit(-1);

  lock_acquire(&filesys_lock);
  if (f_d == STDOUT_FILENO) 
  {
    putbuf(buffer, size);
    status = size;
  }
  else if (f_d != STDIN_FILENO)
  {
    struct file_descriptor *file_descriptor = get_openfile(f_d);
    if (file_descriptor != NULL)
      status = file_write(file_descriptor->file, buffer, size);
  }

  lock_release(&filesys_lock);

  return status;
}

// Changes the next byte to be read or written in open file descriptor to position
 
static void seek(int f_d, unsigned position)
{
  lock_acquire(&filesys_lock);
  struct file_descriptor *file_descriptor = get_openfile(f_d);
  if (file_descriptor != NULL)
    file_seek(file_descriptor->file, position);
  lock_release(&filesys_lock);
  return;
}

static unsigned tell(int f_d)
{
  int status = -1;

  lock_acquire(&filesys_lock);

  struct file_descriptor *file_descriptor = get_openfile(f_d);
  if (file_descriptor != NULL)
    status = file_tell(file_descriptor->file);

  lock_release(&filesys_lock);
  return status;
}