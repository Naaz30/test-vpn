FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libsodium-dev \
    iproute2 \
    iptables \
    iputils-ping

WORKDIR /app

COPY . .

RUN g++ \
    server/server.cpp \
    libs/crypto/crypto.cpp \
    libs/device/device.cpp \
    libs/peer/peer.cpp \
    libs/protocol/protocol.cpp \
    -lsodium \
    -o vpn-server

CMD ["/bin/bash"]