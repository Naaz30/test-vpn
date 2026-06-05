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



void print_key(const char *label, uint8_t *key, int len)
{
    printf("%s: ", label);

    for (int i = 0; i < len; i++)
    {
        printf("%02x", key[i]);
    }

    printf("\n");
}



void derive_client_session_keys(
    uint8_t *server_public_key,
    uint8_t *send_key,
    uint8_t *recv_key)
{
    printf("\n=== CLIENT KEY DERIVATION ===\n");

    print_key(
        "Client Public",
        static_public_key,
        KEY_LEN);

    print_key(
        "Client Private",
        static_private_key,
        KEY_LEN);

    print_key(
        "Server Public",
        server_public_key,
        KEY_LEN);

    if (
        crypto_kx_client_session_keys(
            recv_key,
            send_key,
            static_public_key,
            static_private_key,
            server_public_key) != 0)
    {
        printf("client key derivation failed\n");
        return;
    }

    print_key(
        "Client SEND key",
        send_key,
        SESSION_KEY_LEN);

    print_key(
        "Client RECV key",
        recv_key,
        SESSION_KEY_LEN);

    printf("=============================\n");
}


void derive_server_session_keys(
    uint8_t *client_public_key,
    uint8_t *send_key,
    uint8_t *recv_key)
{
    printf("\n=== SERVER KEY DERIVATION ===\n");

    print_key(
        "Server Public",
        static_public_key,
        KEY_LEN);

    print_key(
        "Server Private",
        static_private_key,
        KEY_LEN);

    print_key(
        "Client Public",
        client_public_key,
        KEY_LEN);

    if (
        crypto_kx_server_session_keys(
            
            recv_key,
            send_key,
            static_public_key,
            static_private_key,
            client_public_key) != 0)
    {
        printf("server key derivation failed\n");
        return;
    }

    print_key(
        "Server SEND key",
        send_key,
        SESSION_KEY_LEN);

    print_key(
        "Server RECV key",
        recv_key,
        SESSION_KEY_LEN);

    printf("=============================\n");
}