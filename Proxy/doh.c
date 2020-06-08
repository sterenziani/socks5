/**
  * doh.c - resolvedor de nombres mediante doh
  *
*/

#include "doh.h"

// main function
size_t
solveDomain(const char* host, int dnsType, buffer *r)
{
  int sockfd;
  struct sockaddr_in server;
  getDohServer(&server);

  // create a socket
  sockfd = socket(ADDRESS_TYPE, SOCK_STREAM, 0);
  if(sockfd<0){
    perror("Socket opening failed!\n");
    return -1;
  }
  fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);

  // creating fd_set to enable select
  fd_set socketSet;
  FD_ZERO(&socketSet);
  FD_SET(sockfd,&socketSet);

  // connect to socket
	if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0 && errno != EINPROGRESS){
    char errno_str[BUFFER_MAX];
    snprintf(errno_str, sizeof errno_str, "Connection failed: errno %d\n", (int) errno);
		perror(errno_str);
		return -1;
	} else if(errno == EINPROGRESS) {
    if(pselect(sockfd+1,NULL,&socketSet,NULL,NULL,NULL)==-1){
      perror("Select error");
      return -1;
    }
	}

  // create dns message
  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[BUFFER_MAX];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);
  size_t contentLength = dnsEncode(host,dnsType,m,BUFFER_MAX);
  char contentLength_str[INT_STRING_MAX];
  snprintf(contentLength_str, sizeof contentLength_str, "%zu", contentLength);


  // make http request
  char server_str[BUFFER_MAX];
  snprintf(server_str, sizeof server_str, "%s:%zu",ADDRESS, (size_t) ADDRESS_PORT);

  //create request buffer
  struct buffer request;
  buffer *req = &request;
  uint8_t direct_buff_req[BUFFER_MAX];
  buffer_init(&request, N(direct_buff_req), direct_buff_req);

  if(httpEncode(server_str, req, m, contentLength_str) < 0){
    perror("Encoding http message failed\n");
    return -1;
  }

  // connect to HTTP
  size_t bytes_sent = sendHttpMessage(sockfd,req);
  if(bytes_sent<0){
    perror("send http message failed");
    return -1;
  }

  //create resposne buffer
  struct buffer response;
  buffer *res = &response;
  uint8_t direct_buff_res[BUFFER_MAX];
  buffer_init(&response, N(direct_buff_res), direct_buff_res);

  // read response

  struct timespec timeout;
  timeout.tv_sec = TIMEOUT_SEC;
  timeout.tv_nsec = 0;

  sigset_t blockset;

  sigemptyset(&blockset);
  //sigaddset(&blockset, SIGINT);
  sigprocmask(SIG_BLOCK, &blockset, NULL);

  while(1){

    //hacer el parseo

    if(pselect(sockfd+1,&socketSet,NULL,NULL,&timeout,&blockset)==-1){
      perror("Select error");
      return -1;
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
        // termine de leer todo
        break;
      }

    }else{
      // timed out
      perror("Connection timed out");
      break;
    }
  }

  // parsear hasta el final

  // falta el decode
  while(buffer_can_read(res)){
    printf("%c",buffer_read(res));
  }

  shutdown(sockfd, SHUT_RDWR);

	return 0;
}

void
getDohServer(struct sockaddr_in* server){
  memset((char *) server,0, sizeof(server));

  server->sin_family	= ADDRESS_TYPE;             // host byte order
  server->sin_port = htons(ADDRESS_PORT);        // assigning the specific port
  server->sin_addr.s_addr = inet_addr(ADDRESS);  // host address
}

size_t
dnsEncode(const char* host, int dnsType, buffer *b, size_t buffSize){

  size_t hostlen = strlen(host);
  const char *hostPointer = host;

  // verificación de lo minimo que debe soportar el paquete
  if(buffSize < (12 + hostlen + 6)){
    return -1;
  }

  // verificacion si el dnsType es AF_INET o AF_INET6
  if(dnsType!= AF_INET && dnsType!=AF_INET6 ){
    return -1;
  }

  //preparing the buffer
  buffer_reset(b);

  //**  header
  // id: 16 bits, relevante si hay varios paquetes
  buffer_write(b,(uint8_t)0x00);
  buffer_write(b,(uint8_t)0x00);
  // qr: 1 bit, 0 para query
  // OPCODE: 4 bit, 0 para standard query
  // AA: 1 bit, Authorative Answer - para respuestas
  // TC: 1 bit, 0 para indicar que el mensaje no es truncado
  // RD: 1 bit, 1 para desear recursion
  buffer_write(b,(uint8_t)0x01);
  // RA: 1 bit, en response define si la recursion existe en el name Server
  // Z: 3 bits, debe ser 0
  // RCODE: 4 bits, response code - indica el status del response
  buffer_write(b,(uint8_t)0x00);
  // QDCOUNT: 16 bits, cantidad de questions, en este caso 1
  buffer_write(b,(uint8_t)0x00);
  buffer_write(b,(uint8_t)0x01);
  // ANCOUNT: 16 bits, cantidad de answers, en este caso 0
  buffer_write(b,(uint8_t)0x00);
  buffer_write(b,(uint8_t)0x00);
  // NSCOUNT: 16 bits, cantidad de name server resource records en
  //  authority records, en este caso 0
  buffer_write(b,(uint8_t)0x00);
  buffer_write(b,(uint8_t)0x00);
  // ARCOUNT: 16 bits, cantidad de resource records en additional records,
  //  en este caso 0
  buffer_write(b,(uint8_t)0x00);
  buffer_write(b,(uint8_t)0x00);

  //**  question section
  // QNAME
  // "secuencia de labels"
  // "primero el octet length y despues dichos octetos"
  // "maxima cantidad de octetos es 255"
  int octetCount=0;
  do{
    // usar strchr para encontrar el siguiente '.'
    char *dot = strchr(hostPointer, '.');
    // los 2 bits superiores de lenght octet deben ser 0 (o sea len < 63)
    size_t labelLen = 0;

    if(dot){
      labelLen = (size_t)(dot-hostPointer);
    }else{
      labelLen = strlen(hostPointer);
    }

    if(labelLen > 63){
      perror("Domain label is too long");
      return -1;
    }

    buffer_write(b,(uint8_t)(labelLen));
    octetCount++;

    while(*hostPointer!='.' && *hostPointer!='\0'){
      buffer_write(b,(uint8_t)(*hostPointer));
      octetCount++;
      hostPointer++;
    }

    if(*hostPointer=='.'){
      hostPointer++;
    }

    if(octetCount>255){
      perror("Domain Name is too long");
      return -1;
    }

  }while(*hostPointer!='\0');
  // 0 al final
  buffer_write(b,(uint8_t)0x00);

  // QTYPE
  buffer_write(b,(uint8_t)0x00);
  if(dnsType==AF_INET){
    buffer_write(b,(uint8_t)0x01);
  }else{
    buffer_write(b,(uint8_t)0x1c);
  }

  // QCLASS - Internet es 1
  buffer_write(b,(uint8_t)0x00);
  buffer_write(b,(uint8_t)0x01);

  return buffer_readable(b);
}

size_t
httpEncode(char* doh, buffer *req, buffer *dnsMessage, char *contentLength){

  buffer_reset(req);

  buffer_write_string(req,"POST /dns-query HTTP/1.1\r\nHost: ");
  buffer_write_string(req,doh);
  buffer_write_string(req,"\r\n");  // modifiy later to sprintf
  buffer_write_string(req,"Content-Type: application/dns-message\r\n");
  buffer_write_string(req,"Accept: application/dns-message\r\n");
  buffer_write_string(req,"Connection: close\r\n");
  buffer_write_string(req,"Content-Length: ");
  buffer_write_string(req,contentLength);
  buffer_write_string(req,"\r\n\r\n");

  // copying the dns-message
  while(buffer_can_read(dnsMessage) && buffer_can_write(req)){
    buffer_write(req,buffer_read(dnsMessage));
  }

  if(!buffer_can_write(req)){
    perror("host name is too long");
    return -1;
  }

  buffer_write_string(req,"\r\n\r\n");

  return buffer_readable(req);
}

size_t
sendHttpMessage(int fd, buffer *req){

  size_t bytes_sent       = 0;
  size_t total_bytes_sent = 0;
  size_t bytes_to_send    = 0;
  uint8_t *readPtr = buffer_read_ptr(req,&bytes_to_send);

  while(total_bytes_sent<bytes_to_send){
    readPtr = buffer_read_ptr(req,&bytes_to_send);
    bytes_sent = send(fd, readPtr, bytes_to_send, 0);
    if(bytes_sent<0){
      return bytes_sent;
    }
    total_bytes_sent += bytes_sent;
    buffer_read_adv(req,bytes_sent);
  }

  return total_bytes_sent;
}
