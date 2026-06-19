#include "./protocol.h"

bool handshake_complete = false;



uint64_t packet_count = 0;
std::array<bool, MAX_PACKET_BITMAP_COUNT> packet_bitmap = {false};


void process_transport_data(
    ServerSession& session,
    uint8_t* buffer,
    int len,
    sockaddr_in* addr)
{
    data_packet_t *pkt =
        (data_packet_t *)buffer;
    
   
    
    peer_t *peer =    find_peer_by_index(addr, pkt->index);

    if (!peer)
        return;

    if (
        peer->state !=
        PEER_ESTABLISHED)
    {
        printf("Packet received from unknown peer!!!!!" );
        return;
    }

    

    uint8_t plaintext[MAX_PAYLOAD_SIZE];

    uint8_t nonce[crypto_secretbox_NONCEBYTES] = {0};

    memcpy(
        nonce,
        &pkt->nonce,
        sizeof(uint64_t));
    
    if(pkt->nonce%MAX_PACKET_BITMAP_COUNT == 0)
    {
        peer->packet_bitmap = {false};
    }
    
    if(peer->packet_bitmap[(pkt->nonce)%MAX_PACKET_BITMAP_COUNT])
    {
        printf(
    "Received VPN packet nonce=%lu already!!!!\n",
    pkt->nonce);
        return ;
    }

    peer->packet_count++;
    peer->packet_bitmap[pkt->nonce%MAX_PACKET_BITMAP_COUNT] = true;
    
    

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

        if(
crypto_secretbox_open_easy(
            plaintext,
            pkt->ciphertext,
            pkt->data_len +
                crypto_secretbox_MACBYTES,
            nonce,
            peer->prev_session_recv_key) != 0
        )
        {
           printf(
            "decrypt failed\n");

        return;
        }
        
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
    session.tunFd,
    plaintext,
    pkt->data_len);
}

void process_transport_client_data(
    ClientSession& session,
    const uint8_t* buffer)
{
    data_packet_t* pkt =
        reinterpret_cast<data_packet_t*>(buffer);

    if (pkt->index != session.serverIndex)
        return;

    uint8_t plaintext[MAX_PAYLOAD_SIZE];

    uint8_t nonce[crypto_secretbox_NONCEBYTES] = {0};

    memcpy(
        nonce,
        &pkt->nonce,
        sizeof(uint64_t));

    if (
        pkt->nonce %
        MAX_PACKET_BITMAP_COUNT == 0)
    {
        session.packetBitmap.fill(false);
    }

    if (
        session.packetBitmap[
            pkt->nonce %
            MAX_PACKET_BITMAP_COUNT])
    {
        printf(
            "Received VPN packet nonce=%lu already\n",
            pkt->nonce);

        return;
    }

    session.packetCount++;

    session.packetBitmap[
        pkt->nonce %
        MAX_PACKET_BITMAP_COUNT] = true;

    bool decrypted = false;

    if (
        crypto_secretbox_open_easy(
            plaintext,
            pkt->ciphertext,
            pkt->data_len +
                crypto_secretbox_MACBYTES,
            nonce,
            session.recvKey.data()) == 0)
    {
        decrypted = true;
    }
    else if (
        crypto_secretbox_open_easy(
            plaintext,
            pkt->ciphertext,
            pkt->data_len +
                crypto_secretbox_MACBYTES,
            nonce,
            session.prevRecvKey.data()) == 0)
    {
        decrypted = true;
    }

    if (!decrypted)
    {
        printf(
            "decrypt failed\n");

        return;
    }

    write(
        session.tunFd,
        plaintext,
        pkt->data_len);
}

/* TODO: Fix functions */
/*Case 1 : server sending data packets outside
  Case 2 : client sending data packets to server - DONE */

void process_tun_packet(
    ServerSession& session)
{
    uint8_t packet[MAX_PAYLOAD_SIZE];

    int len =
    read(
        session.tunFd,
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
    
        out.index = peer->server_index;

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
        sizeof(out.index) +
        sizeof(out.data_len) +
        len +
        crypto_secretbox_MACBYTES;

    sendto(
    session.udpFd,
    &out,
    packet_size,
    0,
    (sockaddr*)&peer->endpoint,
    sizeof(peer->endpoint));
}

void process_tun_client_packet(
    ClientSession& session)
{
    uint8_t packet[MAX_PAYLOAD_SIZE];

    int len =
        read(
            session.tunFd,
            packet,
            sizeof(packet));

    if (len <= 0)
        return;

    data_packet_t out{};

    out.type = PACKET_DATA;
    out.nonce = session.sendNonce++;
    out.index = session.clientIndex;
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
        session.sendKey.data());

    size_t packet_size =
        sizeof(out.type) +
        sizeof(out.nonce) +
        sizeof(out.index) +
        sizeof(out.data_len) +
        len +
        crypto_secretbox_MACBYTES;

    sendto(
        session.udpFd,
        &out,
        packet_size,
        0,
        reinterpret_cast<sockaddr*>(
            &session.serverAddr),
        sizeof(session.serverAddr));
}


