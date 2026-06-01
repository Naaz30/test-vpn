#include "./device.h"

#include <linux/if.h>
#include <linux/if_tun.h>

#include <sys/ioctl.h>

#include <fcntl.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>

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