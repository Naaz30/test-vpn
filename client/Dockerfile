FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libsodium-dev \
    iproute2 \
    iptables \
    iputils-ping \
    curl \
    tcpdump

WORKDIR /app

COPY . .

RUN g++ -std=c++17 \
    client/client.cpp \
    client/utils/crypto/crypto.cpp \
    client/utils/device/device.cpp \
    client/utils/protocol/protocol.cpp \
    client/utils/handshake/handshake.cpp \
    -lsodium \
    -o vpn-client

CMD ["/bin/bash"]