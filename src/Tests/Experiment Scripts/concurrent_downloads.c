#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include<sys/wait.h>

#define CLIENTS 5

int main()
{
	int pids[CLIENTS];
	for(int i=0; i < CLIENTS; i++)
	{
		int pid = fork();
		if (pid == 0)
		{
			char str1[4096];
			
    		sprintf(str1, "curl --output downloaded-file-%d.bin -U juan:juan -x socks5://127.0.0.1:1080 https://speed.hetzner.de/100MB.bin", i);
    		int ret = system(str1);
    		return ret;
		}
		else
			pids[i] = pid;
	}
	for(int i=0; i < CLIENTS; i++)
	{
		wait(NULL);
	}
	printf("Se han descargado %d archivos. Tiene 10 segundos para verlos antes de que se auto-destruyan!\n", CLIENTS);
	sleep(10);
	system("rm *.bin");
	return 0;
}