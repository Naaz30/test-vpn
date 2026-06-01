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

void derive_session_keys(
    uint8_t *peer_public_key,
    uint8_t *send_key,
    uint8_t *recv_key
)
{
    uint8_t shared_secret[32];

    crypto_scalarmult(
        shared_secret,
        static_private_key,
        peer_public_key
    );

    crypto_generichash(
        send_key,
        SESSION_KEY_LEN,
        shared_secret,
        32,
        NULL,
        0
    );

    crypto_generichash(
        recv_key,
        SESSION_KEY_LEN,
        send_key,
        SESSION_KEY_LEN,
        NULL,
        0
    );
}