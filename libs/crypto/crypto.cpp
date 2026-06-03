#include "./crypto.h"

#include <stdio.h>

uint8_t static_public_key[KEY_LEN];
uint8_t static_private_key[KEY_LEN];

int init_sodium()
{
    if (sodium_init() < 0)
    {
        fprintf(stderr,
                "libsodium init failed\n");

        return -1;
    }

    printf("[+] libsodium initialized\n");

    return 0;
}

void init_noise()
{
    crypto_kx_keypair(
        static_public_key,
        static_private_key
    );

    printf("[+] Noise initialized\n");

    printf("[+] Static public key:\n");

    for (int i = 0; i < KEY_LEN; i++)
    {
        printf("%02x",
               static_public_key[i]);
    }

    printf("\n");
}

void derive_client_session_keys(
    uint8_t *server_public_key,
    uint8_t *send_key,
    uint8_t *recv_key)
{
    if (
        crypto_kx_client_session_keys(
            recv_key,
            send_key,
            static_public_key,
            static_private_key,
            server_public_key) != 0)
    {
        printf("client key derivation failed\n");
    }
}


void derive_server_session_keys(
    uint8_t *client_public_key,
    uint8_t *send_key,
    uint8_t *recv_key)
{
    if (
        crypto_kx_server_session_keys(
            send_key,
            recv_key,
            static_public_key,
            static_private_key,
            client_public_key) != 0)
    {
        printf("server key derivation failed\n");
    }
}