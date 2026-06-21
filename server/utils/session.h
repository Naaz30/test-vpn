#pragma once

#include <atomic>

#include "./crypto/crypto.h"


struct ServerSession
{
    int tunFd{-1};
    int udpFd{-1};

    std::atomic<bool> running{true};

    CryptoContext crypto;
};