#include <arpa/inet.h>

#include <sys/select.h>

#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <thread>
#include <sys/random.h>

#include "./utils/crypto/crypto.h"
#include "./utils/session.h"
#include "./utils/device/device.h"
#include "./utils/peer/peer.h"
#include "./utils/protocol/protocol.h"
#include "./utils/handshake/handshake.h"

uint32_t server_index;
uint32_t client_index;

struct sockaddr_in server_addr;

ServerSession session;

void client_checker()
{
    while (true)
    {
        for (int i = 0; i < MAX_PEERS; i++)
        {
            if (peers[i].state == PEER_ESTABLISHED)
            {
                
                auto now =
        std::chrono::system_clock::now();
                uint64_t millis =
        static_cast<uint64_t>(
            std::chrono::duration_cast<
                std::chrono::milliseconds>(
                now.time_since_epoch())
                .count());
                
                
                if (millis - peers[i].last_handshake_ts >= 20 * 60 * 1000)
                {
                    char client_ip_str[INET_ADDRSTRLEN];
                    inet_ntop(
                        AF_INET,
                        &peers[i].vpn_ip,
                        client_ip_str,
                        sizeof(client_ip_str));

                    printf("Disconnecting Peer : %s !!!!! \n", client_ip_str);

                    peers[i].state = PEER_DISCONNECTED;
                }
            }
        }
    }
}

int main()
{
    

    session.tunFd =
        create_tun_device(
            (char *)"tun0");

    if (session.tunFd < 0)
        return -1;

    system(
        "ip addr add 10.0.0.1/24 dev tun0");

    system(
        "ip link set tun0 up");

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
            session.udpFd,
            (sockaddr *)&server_addr,
            sizeof(server_addr)) < 0)
    {
        perror("bind");

        return -1;
    }

   
    init_peers();

    printf("[+] VPN started\n");

    system(
        "sysctl -w net.ipv4.ip_forward=1");

    system(
        "iptables -t nat -A POSTROUTING "
        "-s 10.0.0.0/24 "
        "-o eth0 "
        "-j MASQUERADE");


    std::thread cleanup_thread(client_checker);

    while (true)
    {
        fd_set readfds;

        FD_ZERO(&readfds);

        FD_SET(
            session.udpFd,
            &readfds);

        FD_SET(
            session.tunFd,
            &readfds);

        int maxfd =
            session.tunFd > session.udpFd ? session.tunFd : session.udpFd;

        select(
            maxfd + 1,
            &readfds,
            NULL,
            NULL,
            NULL);

        if (
            FD_ISSET(
                session.udpFd,
                &readfds))
        {
            uint8_t buffer[MAX_PACKET_SIZE];

            struct sockaddr_in
                client_addr;

            socklen_t addr_len =
                sizeof(client_addr);

            int len = recvfrom(
                session.udpFd,
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
    session,
    buffer,
    &client_addr);
            }

            else if (
                type ==
                PACKET_DATA)
            {
                process_transport_data(
    session,
    buffer,
    len,
    &client_addr);
            }
        }

        if (
            FD_ISSET(
                session.tunFd,
                &readfds))
        {
            process_tun_packet(session);
        }
    }

    cleanup_thread.join();

    return 0;
}