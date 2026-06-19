#include "client/client.h"

ClientSession session;

void handshake_worker()
{
    while (session.running)
    {
        int send_handshake =
            client_send_handshake(session);
        if (send_handshake < 0)
        {
            perror("handshake send error");

            return;
        }

        std::this_thread::sleep_for(
            std::chrono::minutes(10));
    }
}

int main()
{
    session.tunFd =
        create_tun_device((char *)"tun0");

    if (session.tunFd < 0)
        return -1;

    session.udpFd = socket(
        AF_INET,
        SOCK_DGRAM,
        0);

    if (session.udpFd < 0)
    {
        perror("socket");
        return -1;
    }

    memset(
        &session.serverAddr,
        0,
        sizeof(session.serverAddr));

    session.serverAddr.sin_family = AF_INET;
    session.serverAddr.sin_port = htons(5555);

    struct hostent *host = gethostbyname(SERVER_HOSTNAME);

    if (host == NULL)
    {
        perror("gethostbyname");
        return -1;
    }

    memcpy(
        &session.serverAddr.sin_addr,
        host->h_addr_list[0],
        host->h_length);

    struct sockaddr_in client_addr;

    memset(
        &client_addr,
        0,
        sizeof(client_addr));

    client_addr.sin_family =
        AF_INET;

    client_addr.sin_port =
        htons(5555);

    client_addr.sin_addr.s_addr =
        INADDR_ANY;

    if (
        bind(
            session.udpFd,
            (sockaddr *)&client_addr,
            sizeof(client_addr)) < 0)
    {
        perror("bind");

        return -1;
    }

    ssize_t rand_bytes =
        getrandom(
            &session.clientIndex,
            sizeof(session.clientIndex),
            0);

    if (rand_bytes != sizeof(session.clientIndex))
    {
        perror("getrandom");
        return -1;
    }

    std::thread handshake_thread(handshake_worker);

    while (session.running)
    {
        fd_set readfds;

        FD_ZERO(&readfds);

        FD_SET(session.tunFd, &readfds);
        FD_SET(session.udpFd, &readfds);

        int maxfd =
            session.tunFd > session.udpFd
                ? session.tunFd
                : session.udpFd;

        int ready =
            select(
                maxfd + 1,
                &readfds,
                nullptr,
                nullptr,
                nullptr);

        if (ready < 0)
        {
            perror("select");
            continue;
        }

        if (FD_ISSET(session.udpFd, &readfds))
        {
            uint8_t buffer[MAX_PACKET_SIZE];

            struct sockaddr_in src_addr;

            socklen_t src_len =
                sizeof(src_addr);

            int len =
                recvfrom(
                    session.udpFd,
                    buffer,
                    sizeof(buffer),
                    0,
                    (sockaddr *)&src_addr,
                    &src_len);

            if (len <= 0)
                continue;

            uint8_t type =
                buffer[0];

            if (type ==
                PACKET_HANDSHAKE_RESP)
            {

                if (len < sizeof(handshake_response_t))
                {
                    continue;
                }

                auto *resp =
                    reinterpret_cast<
                        handshake_response_t *>(buffer);

                std::copy(
                    resp->server_public_key,
                    resp->server_public_key +
                        CryptoContext::KEY_LEN,
                    session.serverPublicKey.begin());

                std::copy(
                    resp->server_ephemeral_public_key,
                    resp->server_ephemeral_public_key +
                        CryptoContext::KEY_LEN,
                    session.serverEphemeralPublicKey.begin());

                session.prevRecvKey =
                    session.recvKey;

                session.prevSendKey =
                    session.sendKey;

                auto keys =
                    session.crypto
                        .deriveClientSessionKeysEphemeral(
                            session.serverPublicKey,
                            session.serverEphemeralPublicKey,
                            session.currentEphemeral);

                session.sendKey = keys.send;
                session.recvKey = keys.recv;

                if (!session.handshakeComplete)
                {
                    configure_tunnel(
                        ntohl(resp->client_ip),
                        ntohl(resp->server_ip),
                        resp->prefix_len);
                }

                session.handshakeComplete = true;

                session.serverIndex =
                    ntohl(resp->index);

                printf(
                    "[+] Handshake complete\n");
            }

            else if (
                type ==
                PACKET_DATA)
            {
                if (!session.handshakeComplete)
                    continue;

                process_transport_client_data(
                    session,
                    buffer);
            }
        }

        if (FD_ISSET(session.tunFd, &readfds))
        {
            if (!session.handshakeComplete)
                continue;

            process_tun_client_packet(session);
        }
    }

    handshake_thread.join();

    return 0;
}