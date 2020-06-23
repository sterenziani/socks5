#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#define CLIENTS 525

int main()
{
	for(int i=0; i < CLIENTS; i++)
	{
		int pid = fork();
		if (pid == 0)
		{
			char str1[4096];
			sprintf(str1, "ncat -C -c \"while true; do echo \\\"GET / HTTP/1.1\r\n\r\n\\\"; sleep 5; done;\" "
				"--proxy 127.0.0.1:1080 --proxy-auth juan:juan --proxy-type socks5 www.google.com 80", i);
    		int ret = system(str1);
    		return ret;
		}
	}
	sleep(60);
	return 0;
}