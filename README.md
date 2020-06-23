# SOCKS5 Proxy Server

Servidor proxy SOCKS5 en C.

### Documentación
Toda la documentación adjuntada se encuentra disponible dentro del directorio docs.

### Código Fuente
Toda el código fuente se encuentra disponible dentro del directorio src.

### Prerequisitos
Es requisito tener docker o similar instalado y definir las variables de entorno CC y DOCKER.

Ejemplos para dichos valores son:
```
export CC=gcc
export DOCKER=docker

```
## Instrucciones de Instalación: proxy
Asegurar de cumplir los Prerequisitos.

```
git clone git@bitbucket.org:itba/pc-2020a-2.git
cd pc2020a-2.git
cd src
make all
```

### Instrucciones de Instalación: doh server
Una vez instalada la imagen de del doh server solo hace falta correr doh-start
```
make doh-build
make doh-start
```

## Instrucciones para el Makefile

* all: compila y linkedita el ejecutable main y el ejecutable manager. No corre el servidor doh, hace falta correrlo por separado.

* main: compila y linkedita el ejecutable main, el servidor proxy socksv5.

* manager: compila y linkedita el ejecutable manager, el cliente que maneja el admin.

* doh-build: descarga el contenedor nginx y arma la imagen doh-nginx. Usar solamente al principio.

* doh-start: Corre el contenedor doh-server desde la imagen doh-nginx.

* doh-stop: Frena la ejecución del doh-server. No hace nada si dicho contenedor no esta corriendo.

* tests: corre los tests presentes en la carpeta Tests.

* clean: borra todos los archivos ejecutables y temporales.

## Instrucciones de Ejecución: proxy
Una vez hecho el make, buscar el ejecutable main dentro de la carpeta src y ejecutarlo. Se puede usar el flag -h para listar los argumentos que puede recibir

```
./main -h
```

## Instrucciones de Ejecución: manager
Una vez hecho el make, buscar el ejecutable manager dentro de la carpeta src y ejecutarlo. Se puede usar el flag -h para listar los argumentos que puede recibir

```
./manager -h
```