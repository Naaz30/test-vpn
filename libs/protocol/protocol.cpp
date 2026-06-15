#include "./protocol.h"

bool handshake_complete = false;

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

    derive_server_session_keys(
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

    resp_pkt.type = PACKET_HANDSHAKE_RESP;

    memcpy(
        resp_pkt.server_public_key,
        static_public_key,
        KEY_LEN);

    resp_pkt.client_ip = peer->vpn_ip;
    std::string ip = "10.0.0.1";
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

     printf(
    "Received VPN packet nonce=%lu payload=%u\n",
    pkt->nonce,
    pkt->data_len);

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

    struct iphdr *ip =
    (struct iphdr *)plaintext;

    char src[INET_ADDRSTRLEN];
char dst[INET_ADDRSTRLEN];

inet_ntop(
    AF_INET,
    &ip->saddr,
    src,
    sizeof(src));

inet_ntop(
    AF_INET,
    &ip->daddr,
    dst,
    sizeof(dst));

printf(
    "IP packet: src=%s dst=%s len=%d proto=%d\n",
    src,
    dst,
    len,
    ip->protocol);


    write(
        tun_fd,
        plaintext,
        pkt->data_len);
}

void process_transport_client_data(
    uint8_t recv_key[SESSION_KEY_LEN], int tun_fd, uint8_t buffer[MAX_PACKET_SIZE])
{

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
            recv_key) != 0)
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

/* TODO: Fix functions */
/*Case 1 : server sending data packets outside
  Case 2 : client sending data packets to server - DONE */

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

void process_tun_client_packet(
    struct sockaddr_in *server,
    uint64_t &send_nonce,
    uint8_t send_key[SESSION_KEY_LEN],
    int udp_fd)
{
    uint8_t packet[MAX_PAYLOAD_SIZE];

    int len =
        read(
            tun_fd,
            packet,
            sizeof(packet));
    
    if (len <= 0)
        return;


    struct iphdr *ip =
    (struct iphdr *)packet;

    char src[INET_ADDRSTRLEN];
char dst[INET_ADDRSTRLEN];

inet_ntop(
    AF_INET,
    &ip->saddr,
    src,
    sizeof(src));

inet_ntop(
    AF_INET,
    &ip->daddr,
    dst,
    sizeof(dst));

printf(
    "IP packet: src=%s dst=%s len=%d proto=%d\n",
    src,
    dst,
    len,
    ip->protocol);

    data_packet_t out;

    memset(
        &out,
        0,
        sizeof(out));

    out.type =
        PACKET_DATA;

    out.nonce =
        send_nonce++;

    out.data_len =
        len;

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
        send_key);

    size_t packet_size =
        sizeof(out.type) +
        sizeof(out.nonce) +
        sizeof(out.data_len) +
        len +
        crypto_secretbox_MACBYTES;

    printf(
    "Sending VPN packet nonce=%lu payload=%u\n",
    out.nonce,
    out.data_len);

    sendto(
        udp_fd,
        &out,
        packet_size,
        0,
        (struct sockaddr *)server,
        sizeof(*server));
}