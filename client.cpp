#include <arpa/inet.h>

#include <sodium.h>

#include <unistd.h>

#include <stdio.h>
#include <string.h>

#include "./protocol/protocol.h"

uint8_t client_public_key[KEY_LEN];
uint8_t client_private_key[KEY_LEN];

int main()
{
    if (sodium_init() < 0)
    {
        printf("libsodium init failed\n");

        return -1;
    }

    crypto_kx_keypair(
        client_public_key,
        client_private_key
    );

    printf("[+] Client public key:\n");

    for (int i = 0; i < KEY_LEN; i++)
    {
        printf("%02x",
               client_public_key[i]);
    }

    printf("\n");

    int sock = socket(
        AF_INET,
        SOCK_DGRAM,
        0
    );

    if (sock < 0)
    {
        perror("socket");

        return -1;
    }

    struct sockaddr_in server_addr;

    memset(
        &server_addr,
        0,
        sizeof(server_addr)
    );

    server_addr.sin_family =
        AF_INET;

    server_addr.sin_port =
        htons(5555);

    inet_pton(
        AF_INET,
        "127.0.0.1",
        &server_addr.sin_addr
    );

    handshake_init_t packet;

    memset(
        &packet,
        0,
        sizeof(packet)
    );

    packet.type =
        PACKET_HANDSHAKE_INIT;

    memcpy(
        packet.client_public_key,
        client_public_key,
        KEY_LEN
    );

    sendto(
        sock,
        &packet,
        sizeof(packet),
        0,
        (sockaddr *)&server_addr,
        sizeof(server_addr)
    );

    printf(
        "[+] Handshake sent\n"
    );

    close(sock);

    return 0;
}

