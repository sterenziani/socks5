/**
  * doh.c - resolvedor de nombres mediante doh
  *
*/

#include "doh.h"

// main function
size_t
solveDomain(const struct doh* dohAddr, const char* host, const char* port, struct addrinfo *hints, struct addrinfo **ret_addrInfo)
{
  int sockfd;
  struct sockaddr_storage server;
  const struct doh* doh_curr = (dohAddr==NULL)?&defaultDoh:dohAddr;

  if(getDohServer(doh_curr, &server)!=0){
    perror("invalid doh address");
    return -1;
  }

  //  to ignore sigpipe
  signal(SIGPIPE, SIG_IGN);

  //  block set
  sigset_t blockset;
  sigemptyset(&blockset);
  sigaddset(&blockset, SIGINT);
  sigaddset(&blockset, SIGPIPE);
  sigprocmask(SIG_BLOCK, &blockset, NULL);

  // create a socket
  sockfd = socket(server.ss_family, SOCK_STREAM, 0);
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
	if (connect(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr)) < 0 && errno != EINPROGRESS){
		perror("Connection failed");
    shutdown(sockfd, SHUT_RDWR);
		return -1;
	} else if(errno == EINPROGRESS) {
    if(pselect(sockfd+1,NULL,&socketSet,NULL,&doh_timeout,&blockset)==-1){
      perror("Select error");
      shutdown(sockfd, SHUT_RDWR);
      return -1;
    }

    int option = 0;
    socklen_t optionLen = sizeof(option);

    if(getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &option, &optionLen) == -1){
  		perror("Couldn't get socket options");
      shutdown(sockfd, SHUT_RDWR);
  		return -1;
    }else if(option != 0){
      errno = option;
  		perror("Connection failed");
      shutdown(sockfd, SHUT_RDWR);
  		return -1;
    }

    if(!FD_ISSET(sockfd, &socketSet)){
      perror("Connect timed out");
      shutdown(sockfd, SHUT_RDWR);
      return -1;
    }
	}

  // create dns message
  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[BUFFER_MAX];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);
  size_t contentLength = dnsEncode(host,hints->ai_family,m,BUFFER_MAX);
  char contentLength_str[INT_STRING_MAX];
  snprintf(contentLength_str, sizeof contentLength_str, "%zu", contentLength);


  // make http request

  //create request buffer
  struct buffer request;
  buffer *req = &request;
  uint8_t direct_buff_req[BUFFER_MAX];
  buffer_init(&request, N(direct_buff_req), direct_buff_req);

  if(httpEncode(doh_curr, req, m, contentLength_str) < 0){
    perror("Encoding http message failed\n");
    shutdown(sockfd, SHUT_RDWR);
    return -1;
  }

  // connect to HTTP
  ssize_t bytes_sent = sendHttpMessage(sockfd,req);
  if(bytes_sent<0){
    perror("send http message failed");
    shutdown(sockfd, SHUT_RDWR);
    return -1;
  }

  //create resposne buffer
  struct buffer response;
  buffer *res = &response;
  uint8_t direct_buff_res[BUFFER_MAX];
  buffer_init(&response, N(direct_buff_res), direct_buff_res);

  // read response

  struct parser_doh *myDohParser = parser_doh_init();

  int n=0;
  do{

    //hacer el parseo
    if(feedParser(myDohParser,res)!=0){
      perror("Parsing error: ");
      parser_doh_destroy(myDohParser);
      shutdown(sockfd, SHUT_RDWR);
      return -1;
    }

    if(pselect(sockfd+1,&socketSet,NULL,NULL,&doh_timeout,&blockset)==-1){
      perror("Select error");
      parser_doh_destroy(myDohParser);
      shutdown(sockfd, SHUT_RDWR);
      return -1;
    }

    if(FD_ISSET(sockfd, &socketSet)){

      if(!buffer_can_write(res)){
        perror("Can't write on response buffer");
        parser_doh_destroy(myDohParser);
        shutdown(sockfd, SHUT_RDWR);
        return -1;
      }
      size_t max_write;
      uint8_t *write_dir = buffer_write_ptr(res,&max_write);

      n = read(sockfd, write_dir, max_write);		//Reads the buffer
      if (n < 0){
        perror("Error on reading");
        parser_doh_destroy(myDohParser);
        shutdown(sockfd, SHUT_RDWR);
        return -1;
      }
      buffer_write_adv(res,n);

    }else{
      // timed out
      perror("Connection timed out");
      parser_doh_destroy(myDohParser);
      shutdown(sockfd, SHUT_RDWR);
      return -1;
    }

    FD_ZERO(&socketSet);
    FD_SET(sockfd,&socketSet);
  }while(n!=0);

  //hacer el parseo
  if(feedParser(myDohParser,res)!=0){
    perror("Parsing error: ");
    parser_doh_destroy(myDohParser);
    shutdown(sockfd, SHUT_RDWR);
    return -1;
  }

  int err;
  *ret_addrInfo = parser_doh_getAddrInfo(myDohParser, &err);

  if(err==0){

    uint32_t port_number = 0;

    for(int i=0; port[i]!=0; i++){
      port_number = port_number*10+(port[i]-'0');
    }

    struct addrinfo *aux = *ret_addrInfo;
    while(aux!=NULL){
      if(aux->ai_family==AF_INET){
        ((struct sockaddr_in*)aux->ai_addr)->sin_port = htons(port_number);
      }else if(aux->ai_family==AF_INET6){
        ((struct sockaddr_in6*)aux->ai_addr)->sin6_port = htons(port_number);
      }

      aux->ai_socktype = SOCK_STREAM;

      aux = aux->ai_next;
    }
  }
  parser_doh_destroy(myDohParser);
  shutdown(sockfd, SHUT_RDWR);
	return err;
}

int
getDohServer(const struct doh* dohAddr, struct sockaddr_storage* server){
  memset((char *) server,0, sizeof(server));

  // determino el tipo de address
  if( inet_pton(AF_INET,dohAddr->ip,&((struct sockaddr_in*)server)->sin_addr.s_addr) ){
    server->ss_family = AF_INET;
    ((struct sockaddr_in *)server)->sin_port = htons(dohAddr->port);
  }else if( inet_pton(AF_INET6,dohAddr->ip,&((struct sockaddr_in6*)server)->sin6_addr.s6_addr) ){
    server->ss_family = AF_INET6;
    ((struct sockaddr_in6 *)server)->sin6_port = htons(dohAddr->port);
  }else{
    return -1;
  }

  return 0;
}

ssize_t
dnsEncode(const char* host, int dnsType, buffer *b, size_t buffSize){

  size_t hostlen = strlen(host);
  const char *hostPointer = host;

  // verificación de lo minimo que debe soportar el paquete
  if(buffSize < (12 + hostlen + 6)){
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
  if(dnsType==AF_INET6){
    buffer_write(b,(uint8_t)0x1c);
  }else{
    // si me llega AF_UNSPEC, lo mando a ipv4
    buffer_write(b,(uint8_t)0x01);
  }

  // QCLASS - Internet es 1
  buffer_write(b,(uint8_t)0x00);
  buffer_write(b,(uint8_t)0x01);

  return (ssize_t) buffer_readable(b);
}

ssize_t
httpEncode(const struct doh* dohAddr, buffer *req, buffer *dnsMessage, char *contentLength){

  char host_str[BUFFER_MAX];
  snprintf(host_str, sizeof host_str, "%s:%hu",dohAddr->host, dohAddr->port);

  buffer_reset(req);

  buffer_write_string(req,"POST ");
  buffer_write_string(req,dohAddr->path);
  buffer_write_string(req," HTTP/1.1\r\nHost: ");
  buffer_write_string(req,host_str);
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

  return (ssize_t)buffer_readable(req);
}

ssize_t
sendHttpMessage(int fd, buffer *req){

  ssize_t bytes_sent       = 0;
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

  return (ssize_t) total_bytes_sent;
}

int
feedParser(struct parser_doh *p, buffer *b){

  while(buffer_can_read(b)){
    if( parser_doh_feed(p, buffer_read(b)) == STAGE_ERROR ){
      return -1;
    }
  }
  buffer_reset(b);
  return 0;
}

void
freedohinfo(struct addrinfo *res){
  struct addrinfo *aux;
  while(res != NULL){
    if(res->ai_family == AF_INET || res->ai_family == AF_INET6){
      free(res->ai_addr);
    }
    aux = res;
    res = res->ai_next;
    free(aux);
  }
}
