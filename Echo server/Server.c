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

#define max(n1,n2)     ((n1)>(n2) ? (n1) : (n2))
  
#define TRUE   1
#define FALSE  0
#define PORT 8888
#define MAX_SOCKETS 30
#define BUFFSIZE 1024
#define PORT_UDP 8888
#define MAX_PENDING_CONNECTIONS   3    // un valor bajo, para realizar pruebas

struct buffer {
    char * buffer;
    size_t len;     // longitud del buffer
    size_t from;    // desde donde falta escribir
};

/**
 Se encarga de escribir la respuesta faltante en forma no bloqueante
 */
void handleWrite(int socket, struct buffer * buffer, fd_set * writefds);
/**
 Limpia el buffer de escritura asociado a un socket
 */
void clear( struct buffer * buffer);

/**
 Crea y "bindea" el socket server UDP
 */
int udpSocket(int port);

/**
 Lee el datagrama del socket, obtiene info asociado con getaddrInfo y envia la respuesta
 */
void handleAddrInfo(int socket);


int main(int argc , char *argv[])
{
    int opt = TRUE;
    int master_socket , addrlen , new_socket , client_socket[MAX_SOCKETS] , max_clients = MAX_SOCKETS , activity, i , sd;
    long valread;
    int max_sd;
    struct sockaddr_in address;
      
    char buffer[BUFFSIZE + 1];  //data buffer of 1K
   
    //set of socket descriptors
    fd_set readfds;
    
    // Agregamos un buffer de escritura asociado a cada socket, para no bloquear por escritura
    struct buffer bufferWrite[MAX_SOCKETS];
    memset(bufferWrite, 0, sizeof bufferWrite);
    
    // y tambien los flags para writes
    fd_set writefds;
 
    //initialise all client_socket[] to 0 so not checked
    for (i = 0; i < max_clients; i++) 
    {
        client_socket[i] = 0;
    }
      
    //create a master socket
    if( (master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0) 
    {
        log(FATAL, "socket failed");
        exit(EXIT_FAILURE);
    }
  
    //set master socket to allow multiple connections , this is just a good habit, it will work without this
    if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0 )
    {
        log(ERROR, "set socket options failed");
     }
  
    //type of socket created
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );
      
    //bind the socket to localhost port 8888
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address))<0) 
    {
        log(FATAL, "bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(master_socket, MAX_PENDING_CONNECTIONS) < 0)
    {
        log(FATAL, "listen");
        exit(EXIT_FAILURE);
    }

    //accept the incoming connection
    addrlen = sizeof(address);
    log(DEBUG, "Waiting for TCP connections on socket %d\n", master_socket);
    
    // Socket UDP para responder con addrInfo
    int udpSock = udpSocket(PORT);
    if ( udpSock < 0) {
        exit(EXIT_FAILURE);
    }

    // Limpiamos el conjunto de escritura
    FD_ZERO(&writefds);
    while(TRUE) 
    {
        //clear the socket set
        FD_ZERO(&readfds);
  
        //add masters sockets to set
        FD_SET(master_socket, &readfds);
        FD_SET(udpSock, &readfds);
        
        max_sd = max(udpSock, master_socket);
         
        //add child sockets to set
        for ( i = 0 ; i < max_clients ; i++) 
        {
            //socket descriptor
            sd = client_socket[i];
             
            //if valid socket descriptor then add to read list
            if(sd > 0)
                FD_SET( sd , &readfds);
             
            //highest file descriptor number, need it for the select function
            if(sd > max_sd)
                max_sd = sd;
        }
  
        //wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
        activity = select( max_sd + 1 , &readfds , &writefds , NULL , NULL);
    
        if ((activity < 0) && (errno!=EINTR)) 
        {
            log(ERROR, "select error, errno=&d",errno);
            continue;
        }
        
        // Servicio UDP
        if(FD_ISSET(udpSock, &readfds)) {
            handleAddrInfo(udpSock);
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
            log(DEBUG, "New connection , socket fd is %d , ip is : %s , port : %d \n" , new_socket , inet_ntoa(address.sin_addr) , ntohs(address.sin_port));
        
            //add new socket to array of sockets
            for (i = 0; i < max_clients; i++) 
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
        
        for(i =0; i < max_clients; i++) {
            sd = client_socket[i];

            if (FD_ISSET(sd, &writefds)) {
                handleWrite(sd, bufferWrite + i, &writefds);
            }
        }
        
        //else its some IO operation on some other socket :)
        for (i = 0; i < max_clients; i++) 
        {
            sd = client_socket[i];
              
            if (FD_ISSET( sd , &readfds)) 
            {
                //Check if it was for closing , and also read the incoming message
                if ((valread = read( sd , buffer, BUFFSIZE)) <= 0)
                {
                    //Somebody disconnected , get his details and print
                    getpeername(sd , (struct sockaddr*)&address , (socklen_t*)&addrlen);
                    log(INFO, "Host disconnected , ip %s , port %d \n" , inet_ntoa(address.sin_addr) , ntohs(address.sin_port));
                      
                    //Close the socket and mark as 0 in list for reuse
                    close( sd );
                    client_socket[i] = 0;
                    
                    FD_CLR(sd, &writefds);
                    // Limpiamos el buffer asociado, para que no lo "herede" otra sesión
                    clear(bufferWrite + i);
                }
                else {
                    log(DEBUG, "Received %zu bytes from socket %d\n", valread, sd);
                    // activamos el socket para escritura y almacenamos en el buffer de salida
                    FD_SET(sd, &writefds);
                    
                    // Tal vez ya habia datos en el buffer
                    // TODO: validar realloc != NULL
                    // TODO: Buscar direcciones
                    bufferWrite[i].buffer = realloc(bufferWrite[i].buffer, bufferWrite[i].len + valread);
                    memcpy(bufferWrite[i].buffer + bufferWrite[i].len, buffer, valread);
                    bufferWrite[i].len += valread;
                }
            }
        }
    }
      
    return 0;
}

void clear( struct buffer * buffer) {
    free(buffer->buffer);
    buffer->buffer = NULL;
    buffer->from = buffer->len = 0;
}

// Hay algo para escribir?
// Si está listo para escribir, escribimos. El problema es que a pesar de tener buffer para poder
// escribir, tal vez no sea suficiente. Por ejemplo podría tener 100 bytes libres en el buffer de
// salida, pero le pido que mande 1000 bytes.Por lo que tenemos que hacer un send no bloqueante,
// verificando la cantidad de bytes que pudo consumir TCP.
void handleWrite(int socket, struct buffer * buffer, fd_set * writefds) {
    size_t bytesToSend = buffer->len - buffer->from;
    if (bytesToSend > 0) {  // Puede estar listo para enviar, pero no tenemos nada para enviar
        log(INFO, "Trying to send %zu bytes to socket %d\n", bytesToSend, socket);
        size_t bytesSent = send(socket, buffer->buffer + buffer->from,bytesToSend,  MSG_DONTWAIT); // | MSG_NOSIGNAL
        log(INFO, "Sent %zu bytes\n", bytesSent);
        
        if ( bytesSent < 0) {
            // Esto no deberia pasar ya que el socket estaba listo para escritura
            // TODO: manejar el error
            log(FATAL, "Error sending to socket %d", socket);
        } else {
            size_t bytesLeft = bytesSent - bytesToSend;
            
            // Si se pudieron mandar todos los bytes limpiamos el buffer
            // y sacamos el fd para el select
            if ( bytesLeft == 0) {
                clear(buffer);
                FD_CLR(socket, writefds);
            } else {
                buffer->from += bytesSent;
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


void handleAddrInfo(int socket) {
    // En el datagrama viene el nombre a resolver
    // Se le devuelve la informacion asociada
    
    char buffer[BUFFSIZE];
    unsigned int len, n;
    
    struct sockaddr_in clntAddr;
    
    n = recvfrom(socket, buffer, BUFFSIZE, 0, ( struct sockaddr *) &clntAddr, &len);
    buffer[n] = '\0';
    log(DEBUG, "UDP received:%s", buffer );
    // TODO: parsear lo recibido para obtener nombre, puerto, etc. del host a conectar. Asumimos viene solo el nombre
    
    // Especificamos solo SOCK_STREAM para que no duplique las respuestas
    struct addrinfo addrCriteria;                   // Criteria for address match
    memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
    addrCriteria.ai_family = AF_UNSPEC;             // Any address family
    addrCriteria.ai_socktype = SOCK_STREAM;         // Only stream sockets
    addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

    struct addrinfo *addrList;

    int fqdn_length = strlen(buffer);
    if(fqdn_length > 0 && buffer[fqdn_length-1] == '\n')
        buffer[fqdn_length-1] = '\0';

    int rtnVal = getaddrinfo(buffer, NULL, &addrCriteria, &addrList);

    if (rtnVal != 0) {
        log(ERROR, "getaddrinfo() failed: %s", gai_strerror(rtnVal));
    }
    
    // Armamos el datagrama con las direcciones de respuesta, separadas por \r\n
    // TODO: hacer una concatenacion segura
    char bufferOut[BUFFSIZE];
    bufferOut[0] = '\0';
    for (struct addrinfo *addr = addrList; addr != NULL; addr = addr->ai_next) {
        struct sockaddr *address = addr->ai_addr;
        char addrBuffer[INET6_ADDRSTRLEN];
        
        void *numericAddress = NULL;
        switch (address->sa_family) {
            case AF_INET:
                numericAddress = &((struct sockaddr_in *) address)->sin_addr;
                break;
            case AF_INET6:
                numericAddress = &((struct sockaddr_in6 *) address)->sin6_addr;
                break;
        }
        if ( numericAddress == NULL) {
            strcat(bufferOut, "[Unknown Type]");
        } else {
            // Convert binary to printable address
            if (inet_ntop(address->sa_family, numericAddress, addrBuffer, sizeof(addrBuffer)) == NULL)
                strcat(bufferOut, "[invalid address]");
            else {
                strcat(bufferOut, addrBuffer);
            }
        }
        strcat(bufferOut, "\r\n");
    }

    // Enviamos respuesta (el sendto no bloquea)
    sendto(socket, bufferOut, strlen(bufferOut),
        0, (const struct sockaddr *) &clntAddr,
        len);

    log(DEBUG, "UDP sent:%s", bufferOut );

    // La primer vez que tiro una sin IP muestra el [Unknown] pero después repite la última IP obtenida
    // TODO: Arreglar eso
    if(bufferOut[0] != '[')
    {
        freeaddrinfo(addrList);
    }
}