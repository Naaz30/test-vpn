#pragma once

#include <arpa/inet.h>

#include <atomic>
#include <cstdint>

#include "./crypto/crypto.h"

struct ClientSession
{
    uint64_t packetCount{0};

    std::array<
        bool,
        MAX_PACKET_BITMAP_COUNT>
        packetBitmap{};
    
    // File descriptors
    int tunFd{-1};
    int udpFd{-1};

    // Runtime state
    std::atomic<bool> running{true};
    bool handshakeComplete{false};

    // Crypto
    CryptoContext crypto;

   
    CryptoContext::EphemeralKeyPair currentEphemeral;

    CryptoContext::SessionKey sendKey{};
    CryptoContext::SessionKey recvKey{};

    CryptoContext::SessionKey prevSendKey{};
    CryptoContext::SessionKey prevRecvKey{};

    CryptoContext::Key serverPublicKey{};

    CryptoContext::Key serverEphemeralPublicKey{};


    // Nonces
    uint64_t sendNonce{0};
    uint64_t recvNonce{0};

    // Peer indexes
    uint32_t clientIndex{0};
    uint32_t serverIndex{0};

    // Network information
    sockaddr_in serverAddr{};
};