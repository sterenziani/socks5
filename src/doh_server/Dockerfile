##
#	Dockerfile para nginx
##

FROM nginx

# Borrando archivos preexistentes para asegurar que esten los nuestros
RUN rm /etc/nginx/conf.d/default.conf
RUN rm -rf /usr/share/nginx/html

# Copiando nuestro sitio y configuración
COPY ${PWD}/html /usr/share/nginx/html
COPY ${PWD}/default.conf /etc/nginx/conf.d/default.conf
