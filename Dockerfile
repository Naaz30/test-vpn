FROM ubuntu:24.04

RUN apt update && \
    apt install -y \
    g++ \
    libsodium-dev \
    iproute2 \
    iputils-ping

WORKDIR /app

COPY . .

RUN g++ \
    main.cpp \
    crypto/crypto.cpp \
    peer/peer.cpp \
    device/device.cpp \
    -lsodium \
    -o vpn

CMD ["/bin/bash"]