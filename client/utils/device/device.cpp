#include "./device.h"

int create_tun_device(char *name)
{
    struct ifreq ifr;

    int fd = open(
        "/dev/net/tun",
        O_RDWR);

    if (fd < 0)
    {
        perror("open");
        return -1;
    }

    memset(
        &ifr,
        0,
        sizeof(ifr));

    ifr.ifr_flags =
        IFF_TUN | IFF_NO_PI;

    strncpy(
        ifr.ifr_name,
        name,
        IFNAMSIZ);

    if (ioctl(
            fd,
            TUNSETIFF,
            &ifr) < 0)
    {
        perror("ioctl");
        close(fd);
        return -1;
    }

    return fd;
}

void configure_tunnel(
    uint32_t client_ip,
    uint32_t server_ip,
    uint8_t prefix_len)
{
    char client_ip_str[INET_ADDRSTRLEN];
    char vpn_gateway_str[INET_ADDRSTRLEN];

    inet_ntop(
        AF_INET,
        &client_ip,
        client_ip_str,
        sizeof(client_ip_str));

    inet_ntop(
        AF_INET,
        &server_ip,
        vpn_gateway_str,
        sizeof(vpn_gateway_str));

    char cmd[256];

    snprintf(
        cmd,
        sizeof(cmd),
        "ip addr add %s/%u dev tun0",
        client_ip_str,
        prefix_len);

    system(cmd);

    system(
        "ip link set tun0 up");

    FILE *fp =
        popen(
            "ip route | grep default | awk '{print $3}'",
            "r");

    if (!fp)
    {
        perror("popen");
        return;
    }

    char docker_gateway[64];

    if (!fgets(
            docker_gateway,
            sizeof(docker_gateway),
            fp))
    {
        pclose(fp);
        return;
    }

    docker_gateway[
        strcspn(
            docker_gateway,
            "\n")] = '\0';

    pclose(fp);

    /*
     * Resolve vpn-server hostname
     */
    struct hostent *host =
        gethostbyname("vpn-server");

    if (!host)
    {
        perror("gethostbyname");
        return;
    }

    char vpn_server_ip[INET_ADDRSTRLEN];

    inet_ntop(
        AF_INET,
        host->h_addr_list[0],
        vpn_server_ip,
        sizeof(vpn_server_ip));

    /*
     * Preserve route to VPN server
     */
    snprintf(
        cmd,
        sizeof(cmd),
        "ip route add %s via %s",
        vpn_server_ip,
        docker_gateway);

    system(cmd);

    /*
     * Route all traffic through VPN
     */
    snprintf(
        cmd,
        sizeof(cmd),
        "ip route replace default via %s dev tun0",
        vpn_gateway_str);

    system(cmd);

    snprintf(
        cmd,
        sizeof(cmd),
        "ip link set dev tun0 mtu 1400");

    system(cmd);


    

    printf(
        "[+] Tunnel configured\n");

    printf(
        "    Client IP : %s/%u\n",
        client_ip_str,
        prefix_len);

    printf(
        "    VPN Gateway : %s\n",
        vpn_gateway_str);

    printf(
        "    Docker Gateway : %s\n",
        docker_gateway);

    printf(
        "    VPN Server : %s\n",
        vpn_server_ip);
}