#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>   
#include <arpa/inet.h>    
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h> 
#include "logger.h"
#include "hello.h"

#define max(n1,n2)     ((n1)>(n2) ? (n1) : (n2))
#define TRUE   1
#define FALSE  0
#define PORT 1080
#define MAX_SOCKETS 30
#define BUFFSIZE 1024
#define MAX_PENDING_CONNECTIONS 3    // un valor bajo, para realizar pruebas
#define IPv4_SIZE 4
#define VERSION5 0x05
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define ARRAY_INIT    {0}
#define RESERVED 0x00

int auth_type;

struct simple_buffer {
    char * simple_buffer;
    size_t len;     // longitud del simple_buffer
    size_t from;    // desde donde falta escribir
};

enum socks_auth_methods {
    NOAUTH = 0x00,
    USERPASS = 0x02,
    NOMETHOD = 0xff
};

enum socks_auth_userpass {
    AUTH_OK = 0x00,
    AUTH_VERSION = 0x01,
    AUTH_FAIL = 0xff
};

enum socks_command {
    CONNECT = 0x01
};

enum socks_command_type {
    IPv4 = 0x01,
    DOMAIN = 0x03,
    IPv6 = 0x04
};

enum socks_status {
    OK = 0x00,
    FAILED = 0x05
};

void clear(struct simple_buffer * simple_buffer) {
    free(simple_buffer->simple_buffer);
    simple_buffer->simple_buffer = NULL;
    simple_buffer->from = simple_buffer->len = 0;
}

static void on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected  = p->data;
    
    if(SOCKS_HELLO_NOAUTHENTICATION_REQUIRED == method || method >= 0xFA)
       *selected = method;
}

void handleWrite(int socket, struct simple_buffer * simple_buffer, fd_set * writefds) {
    size_t bytesToSend = simple_buffer->len - simple_buffer->from;
    if (bytesToSend > 0) {  // Puede estar listo para enviar, pero no tenemos nada para enviar
        log(INFO, "Trying to send %zu bytes to socket %d\n", bytesToSend, socket);
        size_t bytesSent = send(socket, simple_buffer->simple_buffer + simple_buffer->from,bytesToSend,  MSG_DONTWAIT); // | MSG_NOSIGNAL
        log(INFO, "Sent %zu bytes\n", bytesSent);
        
        if ( bytesSent < 0) {
            // Esto no deberia pasar ya que el socket estaba listo para escritura
            // TODO: manejar el error
            log(FATAL, "Error sending to socket %d", socket);
        } else {
            size_t bytesLeft = bytesSent - bytesToSend;
            
            // Si se pudieron mandar todos los bytes limpiamos el simple_buffer
            // y sacamos el fd para el select
            if ( bytesLeft == 0) {
                clear(simple_buffer);
                FD_CLR(socket, writefds);
            } else {
                simple_buffer->from += bytesSent;
            }
        }
    }
}

int udpSocket(int port) {
    
    int sock;
    struct sockaddr_in serverAddr;
    if ( (sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        log(ERROR, "UDP socket creation failed, errno: %d %s", errno, strerror(errno));
        return sock;
    }
    log(DEBUG, "UDP socket %d created", sock);
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family    = AF_INET; // IPv4cle
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    
    if ( bind(sock, (const struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0 )
    {
        log(ERROR, "UDP bind failed, errno: %d %s", errno, strerror(errno));
        close(sock);
        return -1;
    }
    log(DEBUG, "UDP socket bind OK ");
    
    return sock;
}

int connect_ipv4(char* buf, unsigned short int portnum)
{
    int fd;
    char *ip = (char *)buf;
    char address[16];
    snprintf(address, ARRAY_SIZE(address), "%hhu.%hhu.%hhu.%hhu", ip[0], ip[1], ip[2], ip[3]);
    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(ip);
    remote.sin_port = htons(portnum);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0){
        log(ERROR, "connect() in app connect");
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char *argv[])
{
    int opt = TRUE;
    int master_socket;
    int new_socket;
    int max_clients = MAX_SOCKETS;
    int client_socket[MAX_SOCKETS];
    int activity;
    int sd;
    long valread;
    int max_sd;
    struct sockaddr_in address;
    char simple_buffer[BUFFSIZE + 1];
    fd_set readfds;
    fd_set writefds;
    int status[MAX_SOCKETS] = {0};
    uint8_t methods[MAX_SOCKETS];
    struct hello_parser parsers[MAX_SOCKETS];
    int inet_fd[MAX_SOCKETS];

    // Agregamos un simple_buffer de escritura asociado a cada socket, para no bloquear por escritura
    struct simple_buffer simple_bufferWrite[MAX_SOCKETS];
    memset(simple_bufferWrite, 0, sizeof simple_bufferWrite);

    //initialise all client_socket[] to 0 so not checked
    for (int i = 0; i < max_clients; i++) 
    {
        client_socket[i] = 0;
    }

    //create a master socket
    if((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    {
        log(FATAL, "socket failed");
        exit(EXIT_FAILURE);
    }
    //Describe my master socket
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    //bind the socket to localhost port 1080
    if (bind(master_socket, (struct sockaddr*) &address, sizeof(address)) < 0) 
    {
        log(FATAL, "bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(master_socket, MAX_PENDING_CONNECTIONS) < 0)
    {
        log(FATAL, "listen");
        exit(EXIT_FAILURE);
    }

    int addrlen = sizeof(address);
    log(DEBUG, "Waiting for TCP connections on socket %d\n", master_socket);

    // Socket UDP para responder con addrInfo
    int udpSock = udpSocket(PORT);
    if ( udpSock < 0)
        exit(EXIT_FAILURE);

    // Limpiamos el conjunto de escritura
    FD_ZERO(&writefds);
    while(TRUE) 
    {
        //clear the socket set and add masters sockets to set
        FD_ZERO(&readfds);
        FD_SET(master_socket, &readfds);
        FD_SET(udpSock, &readfds);

        max_sd = max(udpSock, master_socket);
         
        //add child sockets to set
        for (int i = 0; i < max_clients; i++) 
        {
            //socket descriptor
            sd = client_socket[i];
             
            //if valid socket descriptor then add to read list
            if(sd > 0)
                FD_SET(sd, &readfds);
             
            //highest file descriptor number, need it for the select function
            if(sd > max_sd)
                max_sd = sd;
        }
  
        //wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
        activity = pselect(max_sd + 1, &readfds, &writefds, NULL, NULL, NULL);
        if ((activity < 0) && (errno!=EINTR))
        {
            log(ERROR, "select error, errno=&d",errno);
            continue;
        }
        
        // Servicio UDP - Si llega algo, corre esta función. Ojito! Abajo está lo que hace TCP
        if(FD_ISSET(udpSock, &readfds))
        {
            //handleAddrInfo(udpSock);
        }
          
        //If something happened on the TCP master socket , then its an incoming connection
        if (FD_ISSET(master_socket, &readfds)) 
        {
            if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)
            {
                log(ERROR, "Accept error on master socket");
                continue;
            }
          
            //inform user of socket number - used in send and receive commands
            log(DEBUG, "New connection , socket fd is %d , ip is : %s , port : %d \n" , new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
            status[new_socket] = 1;

            // Creamos un parser para este socket
            methods[new_socket] = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;
            struct hello_parser parser = {
                .data                     = &(methods[new_socket]),
                .on_authentication_method = on_hello_method,
            };
            parsers[new_socket] = parser;
            hello_parser_init(&(parsers[new_socket]));

            //add new socket to array of sockets
            for (int i = 0; i < max_clients; i++) 
            {
                //if position is empty
                if( client_socket[i] == 0 )
                {
                    client_socket[i] = new_socket;
                    log(DEBUG, "Adding to list of sockets as %d\n" , i);
                    break;
                }
            }
        }
        
        for(int i =0; i < max_clients; i++) {
            sd = client_socket[i];
            if (FD_ISSET(sd, &writefds)) {
                handleWrite(sd, simple_bufferWrite + i, &writefds);
            }
        }
        
        //else its some IO operation on some other socket :)
        for (int i = 0; i < max_clients; i++) 
        {
            sd = client_socket[i];
              
            if (FD_ISSET( sd , &readfds)) 
            {
                //Check if it was for closing , and also read the incoming message
                if ((valread = read(sd, simple_buffer, BUFFSIZE)) <= 0)
                {
                    //Somebody disconnected , get his details and print
                    getpeername(sd , (struct sockaddr*)&address , (socklen_t*)&addrlen);
                    log(INFO, "Host disconnected , ip %s , port %d \n" , inet_ntoa(address.sin_addr) , ntohs(address.sin_port));
                      
                    //Close the socket and mark as 0 in list for reuse
                    close(sd);
                    client_socket[i] = 0;
                    
                    FD_CLR(sd, &writefds);
                    // Limpiamos el simple_buffer asociado, para que no lo "herede" otra sesión
                    clear(simple_bufferWrite + i);
                }
                else {
                    log(DEBUG, "Received %zu bytes from socket %d\n", valread, sd);
                    if(status[sd] == 1)
                    {
                        bool errored = false;
                        buffer b;
                        buffer_init(&(b), valread, (simple_buffer));
                        buffer_write_adv(&(b), valread);

                        enum hello_state st = hello_consume(&b, &(parsers[sd]), &errored);
                        if(st == hello_done)
                        {
                            status[sd] = 2;
                            // Activamos el socket para escritura y encolamos nuestra respuesta para enviar
                            FD_SET(sd, &writefds);
                            uint8_t reply1[] = {VERSION5, methods[sd]};
                            simple_bufferWrite[i].simple_buffer = realloc(simple_bufferWrite[i].simple_buffer, simple_bufferWrite[i].len + 2);
                            memcpy(simple_bufferWrite[i].simple_buffer + simple_bufferWrite[i].len, reply1, 2);
                            simple_bufferWrite[i].len += 2;
                        }
                        else if(st == hello_error_unsupported_version)
                        {
                            log(DEBUG, "Incompatible version!");
                        }
                        else if(errored)
                        {
                            log(DEBUG, "Error!");
                        }
                    }
                    else if(status[sd] == 2)
                    {
                        // TODO: Autenticate si hace falta
                        // TODO: Cambiar esto por un parser
                        inet_fd[i] = -1;
                        if(simple_buffer[0] == 0x05 && simple_buffer[1] == 0x01 && simple_buffer[2] == 0x00)
                        {
                            switch(simple_buffer[3])
                            {
                                case IPv4:      log(DEBUG, "Connect to IPv4 address? Sure!");
                                                char ip[4] = {simple_buffer[4], simple_buffer[5], simple_buffer[6], simple_buffer[7]};
                                                uint8_t port[2] = {simple_buffer[8], simple_buffer[9]};
                                                unsigned short int p = *((unsigned short int*)port);
                                                log(DEBUG, "IP %hhu.%hhu.%hhu.%hhu", ip[0], ip[1], ip[2], ip[3]);
                                                log(DEBUG, "Port %hu", ntohs(p));
                                                inet_fd[i] = connect_ipv4(ip, ntohs(p));
                                                if (inet_fd[i] == -1) {
                                                    log(ERROR, "Abortemos el programa plis!");
                                                }
                                                FD_SET(sd, &writefds);
                                                // Encolamos los primeros bytes en la respuesta
                                                uint8_t reply2[] = {VERSION5, OK, RESERVED, IPv4};
                                                simple_bufferWrite[i].simple_buffer = realloc(simple_bufferWrite[i].simple_buffer, simple_bufferWrite[i].len + 4);
                                                memcpy(simple_bufferWrite[i].simple_buffer + simple_bufferWrite[i].len, reply2, 4);
                                                simple_bufferWrite[i].len += 4;
                                                // Encolamos la IP en la respuesta
                                                simple_bufferWrite[i].simple_buffer = realloc(simple_bufferWrite[i].simple_buffer, simple_bufferWrite[i].len + IPv4_SIZE);
                                                memcpy(simple_bufferWrite[i].simple_buffer + simple_bufferWrite[i].len, ip, IPv4_SIZE);
                                                simple_bufferWrite[i].len += IPv4_SIZE;
                                                // Encolamos el puerto en la respuesta
                                                simple_bufferWrite[i].simple_buffer = realloc(simple_bufferWrite[i].simple_buffer, simple_bufferWrite[i].len + 2);
                                                memcpy(simple_bufferWrite[i].simple_buffer + simple_bufferWrite[i].len, port, 2);
                                                simple_bufferWrite[i].len += 2;
                                                status[sd] = 3;
                                                break;
                                case DOMAIN:    log(DEBUG, "Connect to FQDN? Not implemented yet");
                                                break;
                                case IPv6:      log(DEBUG, "Connect to IPv6 address? Not implemented yet");
                                                break;
                            }
                        }
                        else if(status[sd] == 3)
                        {
                            // TODO: Acá me llegaría un request HTTP. Hay que ver como enviar ese request al servidor de origen.
                        }
                        
                    }
                    // activamos el socket para escritura y almacenamos en el simple_buffer de salida
                    //FD_SET(sd, &writefds);
                    
                    // Tal vez ya habia datos en el simple_buffer
                    // TODO: validar realloc != NULL
                    //ECHO:
                    //simple_bufferWrite[i].simple_buffer = realloc(simple_bufferWrite[i].simple_buffer, simple_bufferWrite[i].len + valread);
                    //memcpy(simple_bufferWrite[i].simple_buffer + simple_bufferWrite[i].len, simple_buffer, valread);
                    //simple_bufferWrite[i].len += valread;

                }
            }
        }
    }
    return 0;
}