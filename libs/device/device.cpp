#include "./device.h"



int create_tun_device(char *name)
{
    struct ifreq ifr;

    int fd = open(
        "/dev/net/tun",
        O_RDWR
    );

    if (fd < 0)
    {
        perror("open");

        return -1;
    }

    memset(
        &ifr,
        0,
        sizeof(ifr)
    );

    ifr.ifr_flags =
        IFF_TUN | IFF_NO_PI;

    strncpy(
        ifr.ifr_name,
        name,
        IFNAMSIZ
    );

    if (
        ioctl(
            fd,
            TUNSETIFF,
            &ifr
        ) < 0
    )
    {
        perror("ioctl");

        close(fd);

        return -1;
    }

    return fd;
}



static void configure_tunnel(
    uint32_t client_ip,
    uint32_t server_ip,
    uint8_t prefix_len)
{
    char ip_str[INET_ADDRSTRLEN];
    char gw_str[INET_ADDRSTRLEN];

    inet_ntop(
        AF_INET,
        &client_ip,
        ip_str,
        sizeof(ip_str));

    inet_ntop(
        AF_INET,
        &server_ip,
        gw_str,
        sizeof(gw_str));

    char cmd[256];

    snprintf(
        cmd,
        sizeof(cmd),
        "ip addr add %s/%u dev tun0",
        ip_str,
        prefix_len);

    system(cmd);

    system(
        "ip link set tun0 up");

    snprintf(
        cmd,
        sizeof(cmd),
        "ip route replace default via %s dev tun0",
        gw_str);

    system(cmd);

    printf(
        "[+] Tunnel configured\n");
    printf(
        "    Client IP : %s/%u\n",
        ip_str,
        prefix_len);
    printf(
        "    Gateway   : %s\n",
        gw_str);
}