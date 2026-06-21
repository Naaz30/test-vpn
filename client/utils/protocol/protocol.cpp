#include "./protocol.h"



void process_transport_client_data(
    ClientSession& session,
    const uint8_t* buffer)
{
    const data_packet_t* pkt =
    reinterpret_cast<const data_packet_t*>(buffer);

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


