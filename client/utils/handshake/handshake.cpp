#include "./handshake.h"

int client_send_handshake(
    ClientSession &session)
{

    session.currentEphemeral =
        session.crypto.generateEphemeral();

    handshake_init_t init_pkt{};

    init_pkt.type = PACKET_HANDSHAKE_INIT;

    init_pkt.index =
        htonl(session.clientIndex);

    auto now =
        std::chrono::system_clock::now();

    uint64_t millis =
        std::chrono::duration_cast<
            std::chrono::milliseconds>(
            now.time_since_epoch())
            .count();

    init_pkt.epoch_ts =
        htobe64(millis);

    memcpy(
        init_pkt.client_static_public_key,
        session.crypto.publicKey().data(),
        CryptoContext::KEY_LEN);

    memcpy(
        init_pkt.client_ephemeral_public_key,
        session.currentEphemeral.publicKey.data(),
        CryptoContext::KEY_LEN);

    ssize_t bytes_sent =
        sendto(
            session.udpFd,
            &init_pkt,
            sizeof(init_pkt),
            0,
            reinterpret_cast<sockaddr *>(
                &session.serverAddr),
            sizeof(session.serverAddr));

    if (bytes_sent < 0)
    {
        perror("sendto");
        return -1;
    }

    if ((size_t)bytes_sent != sizeof(init_pkt))
    {
        fprintf(
            stderr,
            "Partial packet sent\n");
        return -1;
    }

    printf(
        "[+] Handshake sent "
        "(index=%u timestamp=%llu)\n",
        session.clientIndex,
        (unsigned long long)millis);

    return 0;
}