#pragma once

#include "../protocol/protocol.h"
#include "../crypto/crypto.h"
#include "../server_session.h"
#include <chrono>

int client_send_handshake(
    ClientSession &session);