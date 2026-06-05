#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/select.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#include "../libs/crypto/crypto.h"
#include "../libs/device/device.h"
#include "../libs/peer/peer.h"
#include "../libs/protocol/protocol.h"

// File descriptors for tunnel and UDP socket
int tun_fd;
int udp_fd;

// Session exchange Keys
uint8_t send_key[SESSION_KEY_LEN];
uint8_t recv_key[SESSION_KEY_LEN];

// Session NONCE values
uint64_t send_nonce = 0;
uint64_t recv_nonce = 0;

// VPN server public key
uint8_t server_public_key[KEY_LEN];

int main()
{
    if (init_sodium() < 0)
        return -1;

    init_noise();

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

    struct hostent *host = gethostbyname(SERVER_HOSTNAME);

    if (host == NULL)
    {
      perror("gethostbyname");
      return -1;
    }


    memcpy(
    &server_addr.sin_addr,
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
            udp_fd,
            (sockaddr *)&client_addr,
            sizeof(client_addr)) < 0)
    {
        perror("bind");

        return -1;
    }

    handshake_init_t init_pkt;

    memset(
        &init_pkt,
        0,
        sizeof(init_pkt));

    init_pkt.type =
        PACKET_HANDSHAKE_INIT;

    memcpy(
        init_pkt.client_public_key,
        static_public_key,
        KEY_LEN);

    sendto(
        udp_fd,
        &init_pkt,
        sizeof(init_pkt),
        0,
        (sockaddr *)&server_addr,
        sizeof(server_addr));

    printf(
        "[+] Handshake sent\n");

    while (true)
    {
        fd_set readfds;

        FD_ZERO(&readfds);

        FD_SET(tun_fd, &readfds);
        FD_SET(udp_fd, &readfds);

        int maxfd =
            tun_fd > udp_fd
                ? tun_fd
                : udp_fd;

        select(
            maxfd + 1,
            &readfds,
            NULL,
            NULL,
            NULL);

        if (FD_ISSET(udp_fd, &readfds))
        {
            uint8_t buffer[MAX_PACKET_SIZE];

            struct sockaddr_in src_addr;

            socklen_t src_len =
                sizeof(src_addr);

            int len =
                recvfrom(
                    udp_fd,
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
                handshake_response_t *resp =
                    (handshake_response_t *)buffer;

                memcpy(
                    server_public_key,
                    resp->server_public_key,
                    KEY_LEN);

                derive_client_session_keys(
                    server_public_key,
                    send_key,
                    recv_key);

                configure_tunnel(
                    resp->client_ip,
                    resp->server_ip,
                    resp->prefix_len);

                handshake_complete =
                    true;

                printf(
                    "[+] Handshake complete\n");
            }

            else if (
                type ==
                PACKET_DATA)
            {
                if (!handshake_complete)
                    continue;

                process_transport_client_data(
                    recv_key, tun_fd, buffer);
            }
        }

        if (FD_ISSET(tun_fd, &readfds))
        {
            if (!handshake_complete)
                continue;

            process_tun_client_packet(
                &server_addr, send_nonce, send_key, udp_fd);
        }
    }

    return 0;
}