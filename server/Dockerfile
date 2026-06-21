FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libsodium-dev \
    iproute2 \
    iptables \
    iputils-ping \
    tcpdump

WORKDIR /app

COPY . .

RUN g++ \
    server/server.cpp \
    server/utils/crypto/crypto.cpp \
    server/utils/device/device.cpp \
    server/utils/peer/peer.cpp \
    server/utils/protocol/protocol.cpp \
    server/utils/handshake/handshake.cpp \
    -lsodium \
    -o vpn-server

CMD ["/bin/bash"]