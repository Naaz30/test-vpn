#include <arpa/inet.h>

#include <sys/select.h>

#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>

#include "./crypto/crypto.h"
#include "./device/device.h"
#include "./peer/peer.h"
#include "./protocol/protocol.h"

int tun_fd;
int udp_fd;

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




    handshake_response_t resp_pkt;

    memset(
        &resp_pkt,
        0,
        sizeof(resp_pkt));

    resp_pkt.type =    PACKET_HANDSHAKE_RESP;
    resp_pkt.server_public_key = static_public_key;
    resp_pkt.client_ip = peer->vpn_ip;
    std::string ip = "10.0.0.1" ;
    resp_pkt.server_ip = inet_addr(ip.c_str());
    resp_pkt.prefix_len = 24;


     sendto(
        udp_fd,
        &resp_pkt,
        sizeof(resp_pkt),
        0,
        (sockaddr *)&peer->endpoint,
        sizeof(peer->endpoint));
    





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

void send_encrypted_packet(
    peer_t *peer)
{
    uint8_t packet[MAX_PAYLOAD_SIZE];

    int len = read(
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

int main()
{
    if (init_sodium() < 0)
        return -1;

    tun_fd =
        create_tun_device(
            (char *)"tun0");

    if (tun_fd < 0)
        return -1;

    udp_fd = socket(
        AF_INET,
        SOCK_DGRAM,
        0);

    if (udp_fd < 0)
    {
        perror("socket");

        return -1;
    }

    struct sockaddr_in server_addr;

    memset(
        &server_addr,
        0,
        sizeof(server_addr));

    server_addr.sin_family =
        AF_INET;

    server_addr.sin_port =
        htons(5555);

    server_addr.sin_addr.s_addr =
        INADDR_ANY;

    if (
        bind(
            udp_fd,
            (sockaddr *)&server_addr,
            sizeof(server_addr)) < 0)
    {
        perror("bind");

        return -1;
    }

    init_noise();

    init_peers();

    printf("[+] VPN started\n");

    while (true)
    {
        fd_set readfds;

        FD_ZERO(&readfds);

        FD_SET(
            udp_fd,
            &readfds);

        FD_SET(
            tun_fd,
            &readfds);

        int maxfd =
            tun_fd > udp_fd ? tun_fd : udp_fd;

        select(
            maxfd + 1,
            &readfds,
            NULL,
            NULL,
            NULL);

        if (
            FD_ISSET(
                udp_fd,
                &readfds))
        {
            uint8_t buffer[MAX_PACKET_SIZE];

            struct sockaddr_in
                client_addr;

            socklen_t addr_len =
                sizeof(client_addr);

            int len = recvfrom(
                udp_fd,
                buffer,
                sizeof(buffer),
                0,
                (sockaddr *)&client_addr,
                &addr_len);

            if (len <= 0)
            {
                perror(
                    "recvfrom");

                continue;
            }

            uint8_t type =
                buffer[0];

            if (
                type ==
                PACKET_HANDSHAKE_INIT)
            {
                process_handshake_init(
                    buffer,
                    &client_addr);
            }

            else if (
                type ==
                PACKET_DATA)
            {
                process_transport_data(
                    buffer,
                    len,
                    &client_addr);
            }
        }

        if (
            FD_ISSET(
                tun_fd,
                &readfds))
        {
            process_tun_packet();
        }
    }

    return 0;
}