
# **A simple persistence hooking the `open`**

Today we will see a simple example of the `open` , with the aim of maintaining persistence via ssh keys, for example, have you ever thought when a system administrator will add another ssh key in `authorized_keys` and simply the key he put, it doesn't appear and instead yours appears in `authorized_keys`? Or simply, if `authorized_keys` doesn't exist, and with a simple `cat`, your ssh key remains there? Well, that's what we'll see today, and what a headache for the system administrator. (If the sysadmin doesn't know how to remove a .so).

The code hooks the `open`  , to intercept specific paths such as `/root/.ssh/authorized_keys`. It writes an SSH key to that file if the path matches one of the defined targets, and then reopens the file with read and write permissions. If the `O_CREAT` flag is used, the code handles the argument appropriately and calls the original `open` function as necessary. The goal is to ensure that an SSH key is entered in a specific location when these files are accessed.

<p align="center"><img src="image.png"></p>
