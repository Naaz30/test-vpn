#include "./handshake.h"




void process_handshake_init(
    ServerSession& session,
    uint8_t* buffer,
    sockaddr_in* client_addr)
{
    auto* pkt =
        reinterpret_cast<handshake_init_t*>(
            buffer);

    printf(
        "[+] Handshake init received\n");

    peer_t* peer =
        add_peer(
            pkt->client_static_public_key,
            pkt->client_ephemeral_public_key,
            ntohl(pkt->index),
            be64toh(pkt->epoch_ts),
            client_addr);

    if (!peer)
    {
        printf(
            "peer add failed\n");
        return;
    }

    peer->serverEphemeral =
        session.crypto.generateEphemeral();

    auto keys =
        session.crypto
            .deriveServerSessionKeysEphemeral(
                peer->clientStaticPublicKey,
                peer->clientEphemeralPublicKey,
                peer->serverEphemeral);

    establish_session(
        peer,
        keys.send.data(),
        keys.recv.data());

    handshake_response_t resp{};

    resp.type =
        PACKET_HANDSHAKE_RESP;

    memcpy(
        resp.server_static_public_key,
        session.crypto.publicKey().data(),
        CryptoContext::KEY_LEN);

    memcpy(
        resp.server_ephemeral_public_key,
        peer->serverEphemeral.publicKey.data(),
        CryptoContext::KEY_LEN);

    resp.client_ip = peer->vpn_ip;

    resp.server_ip =
        inet_addr("10.0.0.1");

    resp.prefix_len =
        24;

    resp.index =
        htonl(peer->server_index);

    sendto(
        session.udpFd,
        &resp,
        sizeof(resp),
        0,
        reinterpret_cast<sockaddr*>(
            &peer->endpoint),
        sizeof(peer->endpoint));

    printf(
        "[+] Session established\n");
}