FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends hping3 \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["hping3"]
