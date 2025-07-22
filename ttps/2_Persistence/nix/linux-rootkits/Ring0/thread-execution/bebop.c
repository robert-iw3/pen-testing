#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("matheuzsec");
MODULE_DESCRIPTION("Hello space cowboy...");
MODULE_VERSION("1.0");

static int __init spacecowboy_init(void) {
    struct task_struct *task;

    printk(KERN_INFO "[*] Bebop searching for processes in TASK_UNINTERRUPTIBLE state [*]\n");

    rcu_read_lock();
    for_each_process(task) {
        if (READ_ONCE(task->__state) == TASK_UNINTERRUPTIBLE) {
            printk(KERN_INFO "Process found: PID = %d, Name = %s\n",
                   task->pid, task->comm);

            // Change the state to TASK_RUNNING
            WRITE_ONCE(task->__state, TASK_RUNNING);
            wake_up_process(task);

            printk(KERN_INFO "PID = %d changed to TASK_RUNNING\n",
                   task->pid);
            break;
        }
    }
    rcu_read_unlock();

    return 0;
}

static void __exit spacecowboy_exit(void) {
    printk(KERN_INFO "[*] See you later space cowboy... [*]\n");
}

module_init(spacecowboy_init);
module_exit(spacecowboy_exit);
