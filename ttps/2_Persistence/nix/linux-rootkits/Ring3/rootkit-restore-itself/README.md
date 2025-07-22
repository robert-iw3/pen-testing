
# a rootkit that can restore itself

If you delete a file only the filename is removed, and the file (inode) will exist untill the last process using it terminates. So we can use the /proc/self/maps file and /proc/self/map_files/ directory to get access to those files that are still in memory, and copy the rootkit library back to the disk if it's deleted. This will make it harder to remove the rootkit, since it can just restore itself if you delete the rootkit. However, you should still keep in mind that a rootkit is meant to be stealthy so this is not something you'd see in real life.

By Arnout
