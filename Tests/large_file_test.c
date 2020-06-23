#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#define CLIENTS 2000

int main()
{
	int pids[CLIENTS];
	for(int i=0; i < CLIENTS; i++)
	{
		int pid = fork();
		if (pid == 0)
		{
			char str1[4096];

    		sprintf(str1, "time curl --output downloaded-file-%d.bin -U juan:juan -x socks5://127.0.0.1:1080 https://speed.hetzner.de/100MB.bin -s > Tests/time.log", i);
    		int ret = system(str1);
    		return ret;
		}
		else
			pids[i] = pid;
	}
	for(int i=0; i < CLIENTS; i++)
	{
		waitpid(pids[i], 0, WUNTRACED);
	}
	printf("Se han descargado %d imagenes. Tiene 10 segundos para verlas antes de que se auto-destruyan!\n", CLIENTS);
	sleep(10);
	system("rm *.jpg");
	system("rm *.bin");
	return 0;
}
