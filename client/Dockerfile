FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libsodium-dev \
    iproute2 \
    iptables \
    iputils-ping \
    curl

WORKDIR /app

COPY . .

RUN g++ -std=c++17 \
    client/client.cpp \
    libs/crypto/crypto.cpp \
    libs/device/device.cpp \
    libs/peer/peer.cpp \
    libs/protocol/protocol.cpp \
    libs/handshake/handshake.cpp \
    -lsodium \
    -o vpn-client

CMD ["/bin/bash"]