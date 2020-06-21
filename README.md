# SOCKS5 Proxy Server

Servidor proxy SOCKS5 en C.
Es requisito tener las variables de entorno CC y DOCKER.
Ejemplos para dichos valores son:
export CC=gcc
export DOCKER=docker

## Instrucciones para el Makefile

all: compila y linkedita el ejecutable main. No corre el servidor doh, hace falta correrlo por separado

doh-build: descarga el contenedor nginx y arma la imagen doh-nginx. Usar solamente al principio

doh-start: Corre el contenedor doh-server desde la imagen doh-nginx.

doh-stop: Frena la ejecución del doh-server. No hace nada si dicho contenedor no esta corriendo.

tests: corre los tests presentes en la carpeta Tests

clean: borra todos los archivos ejecutables y temporales
