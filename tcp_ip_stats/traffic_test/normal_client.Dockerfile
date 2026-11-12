FROM python:3.13-alpine

RUN apk add --no-cache iproute2

COPY normal_tcp_connections.py normal_http_keepalive.py /usr/local/bin/
RUN chmod 0755 \
    /usr/local/bin/normal_tcp_connections.py \
    /usr/local/bin/normal_http_keepalive.py

ENTRYPOINT ["sleep"]
CMD ["infinity"]
