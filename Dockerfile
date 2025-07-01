FROM ubuntu:24.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN pip install scapy 

WORKDIR /app

COPY src /app
