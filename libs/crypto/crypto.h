#pragma once

#include <sodium.h>
#include <stdint.h>

#define KEY_LEN 32
#define SESSION_KEY_LEN 32

extern uint8_t static_public_key[KEY_LEN];
extern uint8_t static_private_key[KEY_LEN];

int init_sodium();

void init_noise();

void derive_session_keys(
    uint8_t *peer_public_key,
    uint8_t *send_key,
    uint8_t *recv_key
);