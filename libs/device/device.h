#pragma once

#include <linux/if.h>
#include <linux/if_tun.h>

#include <sys/ioctl.h>

#include <fcntl.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>

int create_tun_device(char *name);
static void configure_tunnel(
    uint32_t client_ip,
    uint32_t server_ip,
    uint8_t prefix_len);