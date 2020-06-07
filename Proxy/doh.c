/**
  * doh.c - resolvedor de nombres mediante doh
  *
*/

#include "doh.h"

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
