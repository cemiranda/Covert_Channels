FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    --no-install-recommends python3 python3-pip \
    libpcap-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install  --break-system-packages scapy cryptography requests

WORKDIR /app

COPY src/ /app/

COPY certs /app/
