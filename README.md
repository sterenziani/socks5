# SOCKS5 Proxy Server

Servidor proxy SOCKS5 en C.

## Instrucciones para el Makefile
doh-build: descarga el contenedor nginx y arma la imagen doh-nginx. Usar solamente al principio

doh-start: Corre el contenedor doh-server desde la imagen doh-nginx.

doh-stop: Frena la ejecución del doh-server. No hace nada si dicho contenedor no esta corriendo.

clean: borra todos los archivos ejecutables y temporales
