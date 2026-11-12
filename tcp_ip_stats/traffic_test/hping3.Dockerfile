FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends hping3 \
    && rm -rf /var/lib/apt/lists/*

COPY hping3_multi_source.sh /usr/local/bin/hping3_multi_source.sh
RUN chmod 0755 /usr/local/bin/hping3_multi_source.sh

ENTRYPOINT ["hping3"]
