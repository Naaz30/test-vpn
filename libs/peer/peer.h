#pragma once

#include <arpa/inet.h>
#include <stdint.h>
#include <cstring>

#define MAX_PEERS 32
#define KEY_LEN 32
#define SESSION_KEY_LEN 32


enum
{
    PEER_DISCONNECTED,
    PEER_HANDSHAKING,
    PEER_ESTABLISHED
};

typedef struct
{
    uint8_t public_key[KEY_LEN];

    uint8_t session_send_key[SESSION_KEY_LEN];
    uint8_t session_recv_key[SESSION_KEY_LEN];

    uint64_t send_nonce;
    uint64_t recv_nonce;

    struct sockaddr_in endpoint;

    uint32_t vpn_ip;

    int state;

} peer_t;

extern peer_t peers[MAX_PEERS];
extern int peer_count;

void init_peers();

peer_t *add_peer(
    uint8_t *public_key,
    struct sockaddr_in *addr
);

peer_t *find_peer_by_ip(
    struct sockaddr_in *addr
);

void establish_session(
    peer_t *peer,
    uint8_t *send_key,
    uint8_t *recv_key
);

peer_t *find_peer_by_vpn_ip(
    uint32_t addr
);