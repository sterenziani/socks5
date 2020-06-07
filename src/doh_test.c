/*
** doh_test.c -- tries to make a http request
* currently has all functions that doh.c should have
*/

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "aux/buffer.h"
#include "doh.h"

#define ADDRESS_PORT 8080
#define ADDRESS "127.0.0.1"
#define ADDRESS_TYPE AF_INET
#define TIMEOUT_SEC 5

//test variable
#define HOST "google.com"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define BUFFER_MAX 1024
#define INT_STRING_MAX 11

int main(int argc, char *argv[])
{
  int sockfd;
  struct sockaddr_in server;

  // Zeroes out the whole struct, thus resetting the values
  memset((char *) &server,0, sizeof(server));

  server.sin_family	= ADDRESS_TYPE;             // host byte order
  server.sin_port = htons(ADDRESS_PORT);        // assigning the specific port
  server.sin_addr.s_addr = inet_addr(ADDRESS);  // host address

  // create a socket
  sockfd = socket(ADDRESS_TYPE, SOCK_STREAM, 0);
  if(sockfd<0){
    perror("Socket opening failed!\n");
    return 1;
  }
  //fcntl(sockfd, F_SETFL, O_NONBLOCK);

  // connect to socket
	if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0){
		perror("Connection failed!\n");
		return 1;
	} else {
		printf("Connect successful\n");
	}

  // create dns message
  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[BUFFER_MAX];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);
  size_t contentLength = dnsEncode(HOST,AF_INET,m,BUFFER_MAX);
  char contentLength_str[INT_STRING_MAX];
  snprintf(contentLength_str, sizeof contentLength_str, "%zu", contentLength);


  // make http request

  //create request buffer
  struct buffer request;
  buffer *req = &request;
  uint8_t direct_buff_req[BUFFER_MAX];
  buffer_init(&request, N(direct_buff_req), direct_buff_req);

  buffer_write_string(req,"POST /dns-query HTTP/1.1\r\nHost: ");
  buffer_write_string(req,ADDRESS);
  buffer_write_string(req,":");
  buffer_write_string(req,"8080\r\n");  // modifiy later to sprintf
  buffer_write_string(req,"Content-Type: application/dns-message\r\n");
  buffer_write_string(req,"Accept: application/dns-message\r\n");
  buffer_write_string(req,"Connection: close\r\n");
  buffer_write_string(req,"Content-Length: ");
  buffer_write_string(req,contentLength_str);
  buffer_write_string(req,"\r\n\r\n");

  // copying the dns-message
  while(buffer_can_read(m) && buffer_can_write(req)){
    buffer_write(req,buffer_read(m));
  }

  if(!buffer_can_write(req)){
    perror("host name is too long");
    return -1;
  }

  buffer_write_string(req,"\r\n\r\n");

  // connect to HTTP
  size_t bytes_sent       = 0;
  size_t total_bytes_sent = 0;
  size_t bytes_to_send    = buffer_readable(req);

  while(total_bytes_sent<bytes_to_send){
    bytes_sent = send(sockfd, req->read, buffer_readable(req), 0);
    total_bytes_sent += bytes_sent;
    buffer_read_adv(req,bytes_sent);
  }

  //create resposne buffer
  struct buffer response;
  buffer *res = &response;
  uint8_t direct_buff_res[BUFFER_MAX];
  buffer_init(&response, N(direct_buff_res), direct_buff_res);

  // read response
  fd_set socketSet;
  FD_ZERO(&socketSet);
  FD_SET(sockfd,&socketSet);

  struct timespec timeout;
  timeout.tv_sec = TIMEOUT_SEC;

  sigset_t blockset;

  sigemptyset(&blockset);
  //sigaddset(&blockset, SIGINT);
  sigprocmask(SIG_BLOCK, &blockset, NULL);

  while(1){
    if(pselect(sockfd+1,&socketSet,NULL,NULL,&timeout,&blockset)==-1){
      perror("Problem with select");
      return 1;
    }

    if(FD_ISSET(sockfd, &socketSet)){

      if(!buffer_can_write(res)){
        perror("Can't write on response buffer");
        break;
      }
      size_t max_write;
      uint8_t *write_dir = buffer_write_ptr(res,&max_write);

      int n;
      n = read(sockfd, write_dir, max_write);		//Reads the buffer
      buffer_write_adv(res,n);
      if (n < 0){
        perror("Error on reading");
        break;
      }else if(n == 0){
        break;
      }

    }else{
      // timed out
      perror("Connection timed out");
      break;
    }
  }

  while(buffer_can_read(res)){
    printf("%c",buffer_read(res));
  }

  shutdown(sockfd, SHUT_RDWR);

	return 0;
}
