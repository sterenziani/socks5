#ifndef __logger_h_
	#define __logger_h_
	#include <stdio.h>
	#include "timestamp.h"

	typedef enum {DEBUG=0, INFO, LOGGER_ERROR, FATAL} LOG_LEVEL;

     extern LOG_LEVEL current_level;

     /**
	*  Minimo nivel de log a informar. Cualquier llamada a log con un nivel mayot a newLevel sera ignorada
	**/
     void setLogLevel(LOG_LEVEL newLevel);

     char * levelDescription(LOG_LEVEL level);

	#define log(level, fmt, ...)   if(level >= current_level) {\
			fprintf (stderr, "%s: %s:%d\t\t", levelDescription(level), __FILE__, __LINE__); \
						char* log_timestamp = time_stamp();\
            fprintf(stderr, "%s\t\t", log_timestamp);\
						free(log_timestamp);\
						fprintf(stderr, fmt, ##__VA_ARGS__); \
    			fprintf(stderr,"\n");  }

#endif
