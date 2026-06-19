#pragma once

#include <stdint.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <sys/ioctl.h>

#include <fcntl.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

int create_tun_device(char *name);

void configure_tunnel(
    uint32_t client_ip,
    uint32_t server_ip,
    uint8_t prefix_len);