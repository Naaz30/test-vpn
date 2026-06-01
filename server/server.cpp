#include <arpa/inet.h>

#include <sys/select.h>

#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>

#include "./libs/crypto/crypto.h"
#include "./libs/device/device.h"
#include "./libs/peer/peer.h"
#include "./libs/protocol/protocol.h"


int tun_fd;
int udp_fd;


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