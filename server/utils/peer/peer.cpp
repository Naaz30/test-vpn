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
    const uint8_t *clientStatic,
    const uint8_t *clientEphemeral,
    uint32_t index,
    uint64_t epoch_ts,
    sockaddr_in *addr)
{

    peer_t *p = nullptr;

    for (int i = 0; i < peer_count; i++)
    {
        if (
            memcmp(
                peers[i].clientStaticPublicKey.data(),
                clientStatic,
                CryptoContext::KEY_LEN) == 0)
        {
            p = &peers[i];
            break;
        }
    }
    
    if (p == nullptr)
    for (int i = 0; i < peer_count; i++)
    {
        if (
            peers[i].client_index ==
            index)
        {
            p = &peers[i];
            break;
        }
    }

    std::string ip;
    if (p == nullptr)
    {
        if (peer_count >= MAX_PEERS)
        {
            return nullptr;
        }

        p = &peers[peer_count];

        *p = {};

        // Assign VPN IP
        ip =
            "10.0.0." +
            std::to_string(peer_count + 2);

        p->vpn_ip = inet_addr(ip.c_str());

        p->client_index = index;

        ssize_t rand_bytes =
            getrandom(
                &p->server_index,
                sizeof(p->server_index),
                0);

        if (rand_bytes != sizeof(p->server_index))
        {
            perror("getrandom");
            return nullptr;
        }

        // Initialize session state
        memset(
            p->session_send_key,
            0,
            SESSION_KEY_LEN);

        memset(
            p->session_recv_key,
            0,
            SESSION_KEY_LEN);

        p->send_nonce = 0;
        p->recv_nonce = 0;
        p->packet_count = 0;
        p->packet_bitmap = {false};
        peer_count++;
    }

    memcpy(
        p->clientStaticPublicKey.data(),
        clientStatic,
        CryptoContext::KEY_LEN);

    memcpy(
        p->clientEphemeralPublicKey.data(),
        clientEphemeral,
        CryptoContext::KEY_LEN);

    memcpy(
        p->prev_session_recv_key,
        p->session_recv_key,
        SESSION_KEY_LEN);

    memcpy(
        p->prev_session_send_key,
        p->session_send_key,
        SESSION_KEY_LEN);

    // Store handshake timestamp
    p->last_handshake_ts = epoch_ts;

    // Store endpoint
    memcpy(
        &p->endpoint,
        addr,
        sizeof(struct sockaddr_in));

    p->state = PEER_HANDSHAKING;

    char ip_str[INET_ADDRSTRLEN];

    inet_ntop(
        AF_INET,
        &p->vpn_ip,
        ip_str,
        sizeof(ip_str));

    printf(
        "[+] Peer %s "
        "(client_index=%u, server_index=%u)\n",
        ip_str,
        p->client_index,
        p->server_index);

    return p;
}

peer_t *find_peer_by_ip(
    struct sockaddr_in *addr)
{
    for (int i = 0; i < peer_count; i++)
    {
        if (
            peers[i].endpoint.sin_addr.s_addr ==
                addr->sin_addr.s_addr &&

            peers[i].endpoint.sin_port ==
                addr->sin_port)
        {
            return &peers[i];
        }
    }

    return NULL;
}

peer_t *find_peer_by_index(
    struct sockaddr_in *addr,
    uint32_t index)
{
    for (int i = 0; i < peer_count; i++)
    {
        if (peers[i].client_index == index

        )
        {

            peers[i].endpoint.sin_addr.s_addr =
                addr->sin_addr.s_addr;

            peers[i].endpoint.sin_port =
                addr->sin_port;

            return &peers[i];
        }
    }

    return NULL;
}

peer_t *find_peer_by_vpn_ip(
    uint32_t addr)
{
    for (int i = 0; i < peer_count; i++)
    {
        if (
            peers[i].vpn_ip == addr)
        {
            return &peers[i];
        }
    }

    return NULL;
}

void establish_session(
    peer_t* peer,
    const uint8_t* send_key,
    const uint8_t* recv_key)
{
    memcpy(
        peer->session_send_key,
        send_key,
        SESSION_KEY_LEN);

    memcpy(
        peer->session_recv_key,
        recv_key,
        SESSION_KEY_LEN);

    peer->send_nonce = 0;
    peer->recv_nonce = 0;

    peer->state = PEER_ESTABLISHED;
}