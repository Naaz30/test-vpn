#pragma once

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/select.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <thread>
#include <array>
#include <algorithm>

#include "./utils/device/device.h"
#include "./utils/protocol/protocol.h"
#include "./utils/handshake/handshake.h"
#include "./utils/server_session.h"