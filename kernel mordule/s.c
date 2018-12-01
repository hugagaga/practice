/*
  A kernel module to scan the list of processes, search for a specific progress name
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h> // task_struct definition
#include <asm/unistd.h>
#include <linux/list.h>
#include <linux/init_task.h>
#include <stdbool.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>

#define SYS_CALL_TABLE "sys_call_table"
#define SCANNER __NR_tuxcall

#ifndef __KERNEL__
#define __KERNEL__
#endif

static ulong *syscall_table;
static void *original_syscall;
static char buffer[50];
char parent[50];

// Scan Processes return whether or not find the expected process
pid_t scanProcesses(char* processName) {
  // The struct used for info of a process
  struct task_struct* task;
  bool found = false;
  pid_t pid = 0;
  //copy the process name passed from user space
  if (copy_from_user(buffer, processName, 20)) {
    return -EFAULT;
  }
  // Go through the list of processes
  for_each_process(task) {
    if(strcmp(task->comm,buffer)==0){
      found = true;
      pid = task->pid;
      break;
    }
  }
  if (found) {
    printk(KERN_INFO "%s found", processName);
  } else {
    printk(KERN_INFO "%s not found", processName);
  }
  return pid;
} 

static int is_syscall_table(ulong *p)
{
  return ((p != NULL) && (p[__NR_close] == (ulong)sys_close));
}

//enable page writing
static int page_read_write(ulong address)
{
  uint level;
  pte_t *pte = lookup_address(address, &level);

  if(pte->pte &~ _PAGE_RW)
  pte->pte |= _PAGE_RW;
  return 0;
}

//disable page writing
static int page_read_only(ulong address)
{
  uint level;
  pte_t *pte = lookup_address(address, &level);
  pte->pte = pte->pte &~ _PAGE_RW;
  return 0;
}

//replace existing system call with custom system call
static void replace_syscall(ulong offset, ulong func_address)
{
  //get system call table address  
  syscall_table = (ulong *)kallsyms_lookup_name(SYS_CALL_TABLE);
  if (is_syscall_table(syscall_table)) {
    printk(KERN_INFO "Syscall table address : %p\n", syscall_table);
    page_read_write((ulong)syscall_table);
    original_syscall = (void *)(syscall_table[offset]);
    printk(KERN_INFO "Syscall at offset %lu : %p\n", offset, original_syscall);
    printk(KERN_INFO "Custom syscall address %p\n", scanProcesses);
    syscall_table[offset] = func_address;
    printk(KERN_INFO "Syscall hijacked\n");
    printk(KERN_INFO "Syscall at offset %lu : %p\n", offset, (void *)syscall_table[offset]);
    page_read_only((ulong)syscall_table);
  }
}

// Initialization of module
int __init init_MyKernelModule(void)
{
  printk("Process Scan system call loaded.\n");
  //load custom system call
  replace_syscall(SCANNER, (ulong)scanProcesses);
  return 0;
}

// Exit of module
void __exit exit_MyKernelModule(void)
{
  //recover
  page_read_write((ulong)syscall_table);
  syscall_table[SCANNER] = (ulong)original_syscall;
  page_read_only((ulong)syscall_table);
  printk("Process Scan Module Exit.\n");
  printk("Syscall tabel recovered.\n");
  return;
}

module_init(init_MyKernelModule);
module_exit(exit_MyKernelModule);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A kernel module to scan processes for a specfic process");

