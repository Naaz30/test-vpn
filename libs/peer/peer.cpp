#include "./peer.h"

#include <string>
#include <arpa/inet.h>

peer_t peers[MAX_PEERS];

int peer_count;

void init_peers()
{
    peer_count = 0;

    for (int i = 0; i < MAX_PEERS; i++)
    {
        peers[i].state = PEER_DISCONNECTED;

        peers[i].send_nonce = 0;
        peers[i].recv_nonce = 0;
    }
}

peer_t *add_peer(
    uint8_t *public_key,
    struct sockaddr_in *addr
)
{
    if (peer_count >= MAX_PEERS)
        return NULL;

    peer_t *p = &peers[peer_count];
    
    std::string ip = "10.0.0." + std::to_string(peer_count + 2);
    p->vpn_ip = inet_addr(ip.c_str());

    memcpy(
        p->public_key,
        public_key,
        KEY_LEN
    );

    memset(
        p->session_send_key,
        0,
        SESSION_KEY_LEN
    );

    memset(
        p->session_recv_key,
        0,
        SESSION_KEY_LEN
    );

    p->send_nonce = 0;
    p->recv_nonce = 0;

    memcpy(
        &p->endpoint,
        addr,
        sizeof(struct sockaddr_in)
    );

    p->state = PEER_HANDSHAKING;

    peer_count++;

    return p;
}

peer_t *find_peer_by_ip(
    struct sockaddr_in *addr
)
{
    for (int i = 0; i < peer_count; i++)
    {
        if (
            peers[i].endpoint.sin_addr.s_addr ==
            addr->sin_addr.s_addr &&

            peers[i].endpoint.sin_port ==
            addr->sin_port
        )
        {
            return &peers[i];
        }
    }

    return NULL;
}


peer_t *find_peer_by_vpn_ip(
    uint32_t addr
)
{
    for (int i = 0; i < peer_count; i++)
    {
        if (
            peers[i].vpn_ip == addr
        )
        {
            return &peers[i];
        }
    }

    return NULL;
}

void establish_session(
    peer_t *peer,
    uint8_t *send_key,
    uint8_t *recv_key
)
{
    memcpy(
        peer->session_send_key,
        send_key,
        SESSION_KEY_LEN
    );

    memcpy(
        peer->session_recv_key,
        recv_key,
        SESSION_KEY_LEN
    );

    peer->state = PEER_ESTABLISHED;
}