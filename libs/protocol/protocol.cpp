#pragma once

#include "./protocol.h"

void process_handshake_init(
    uint8_t *buffer,
    struct sockaddr_in *client_addr)
{
    handshake_init_t *pkt =
        (handshake_init_t *)buffer;

    printf(
        "[+] Handshake init received\n");

    uint8_t send_key[SESSION_KEY_LEN];

    uint8_t recv_key[SESSION_KEY_LEN];

    derive_session_keys(
        pkt->client_public_key,
        send_key,
        recv_key);

    peer_t *peer = add_peer(
        pkt->client_public_key,
        client_addr);

    if (!peer)
    {
        printf("peer add failed\n");

        return;
    }

    establish_session(
        peer,
        send_key,
        recv_key);

    printf(
        "[+] Session established\n");
}



void process_transport_data(
    uint8_t *buffer,
    int len,
    struct sockaddr_in *addr)
{
    peer_t *peer =
        find_peer_by_ip(addr);

    if (!peer)
        return;

    if (
        peer->state !=
        PEER_ESTABLISHED)
    {
        return;
    }

    data_packet_t *pkt =
        (data_packet_t *)buffer;

    uint8_t plaintext[MAX_PAYLOAD_SIZE];

    uint8_t nonce[crypto_secretbox_NONCEBYTES] = {0};

    memcpy(
        nonce,
        &pkt->nonce,
        sizeof(uint64_t));

    if (
        crypto_secretbox_open_easy(
            plaintext,
            pkt->ciphertext,
            pkt->data_len +
                crypto_secretbox_MACBYTES,
            nonce,
            peer->session_recv_key) != 0)
    {
        printf(
            "decrypt failed\n");

        return;
    }

    write(
        tun_fd,
        plaintext,
        pkt->data_len);
}



void process_tun_packet()
{
    uint8_t packet[MAX_PAYLOAD_SIZE];

    int len = read(
        tun_fd,
        packet,
        sizeof(packet));

    if (len <= 0)
        return;

    struct iphdr *ip =
        (struct iphdr *)packet;

    uint32_t dst =
        ip->daddr;

    peer_t *peer =
        find_peer_by_vpn_ip(dst);

    if (!peer)
    {
        printf(
            "No VPN peer for %s\n",
            inet_ntoa(
                *(struct in_addr *)&dst));

        return;
    }

    data_packet_t out;

    memset(
        &out,
        0,
        sizeof(out));

    out.type = PACKET_DATA;

    out.nonce =
        peer->send_nonce++;

    out.data_len = len;

    uint8_t nonce[crypto_secretbox_NONCEBYTES] = {0};

    memcpy(
        nonce,
        &out.nonce,
        sizeof(uint64_t));

    crypto_secretbox_easy(
        out.ciphertext,
        packet,
        len,
        nonce,
        peer->session_send_key);

    size_t packet_size =
        sizeof(out.type) +
        sizeof(out.nonce) +
        sizeof(out.data_len) +
        len +
        crypto_secretbox_MACBYTES;

    sendto(
        udp_fd,
        &out,
        packet_size,
        0,
        (sockaddr *)&peer->endpoint,
        sizeof(peer->endpoint));
}



void process_tun_packet((sockaddr *)server)
{
    uint8_t packet[MAX_PAYLOAD_SIZE];

    int len =
        read(
            tun_fd,
            packet,
            sizeof(packet));

    if (len <= 0)
        return;

    data_packet_t out;

    memset(
        &out,
        0,
        sizeof(out));

    out.type =
        PACKET_DATA;

    out.nonce =
        0;

    out.data_len =
        len;

    uint8_t nonce[
        crypto_secretbox_NONCEBYTES] = {0};

    memcpy(
        nonce,
        &out.nonce,
        sizeof(uint64_t));

    crypto_secretbox_easy(
        out.ciphertext,
        packet,
        len,
        nonce,
        send_key);

    size_t packet_size =
        sizeof(out.type) +
        sizeof(out.nonce) +
        sizeof(out.data_len) +
        len +
        crypto_secretbox_MACBYTES;

    sendto(
        udp_fd,
        &out,
        packet_size,
        0,
        (sockaddr *)&server,
        sizeof(server));
}