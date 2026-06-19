#pragma once

#include "../protocol/protocol.h"
#include "../crypto/crypto.h"
#include "../peer/peer.h"
#include "../session.h"


void process_handshake_init(
    ServerSession& session,
    uint8_t* buffer,
    sockaddr_in* client_addr);