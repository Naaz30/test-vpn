#include "crypto.h"

#include <stdexcept>

#include <sodium.h>
#include <cstring>

CryptoContext::CryptoContext()
{
    if (sodium_init() < 0)
    {
        throw std::runtime_error(
            "libsodium initialization failed");
    }

    crypto_kx_keypair(
        publicKey_.data(),
        privateKey_.data());
}

CryptoContext::~CryptoContext()
{
    sodium_memzero(
        privateKey_.data(),
        privateKey_.size());
}

const CryptoContext::Key &
CryptoContext::publicKey() const noexcept
{
    return publicKey_;
}

CryptoContext::SessionKeys
CryptoContext::deriveClientSessionKeys(
    const Key &serverPublicKey) const
{
    SessionKeys keys;

    if (
        crypto_kx_client_session_keys(
            keys.recv.data(),
            keys.send.data(),
            publicKey_.data(),
            privateKey_.data(),
            serverPublicKey.data()) != 0)
    {
        throw std::runtime_error(
            "client session key derivation failed");
    }

    return keys;
}

CryptoContext::SessionKeys
CryptoContext::deriveServerSessionKeys(
    const Key &clientPublicKey) const
{
    SessionKeys keys;

    if (
        crypto_kx_server_session_keys(
            keys.recv.data(),
            keys.send.data(),
            publicKey_.data(),
            privateKey_.data(),
            clientPublicKey.data()) != 0)
    {
        throw std::runtime_error(
            "server session key derivation failed");
    }

    return keys;
}

CryptoContext::EphemeralKeyPair
CryptoContext::generateEphemeral() const
{
    EphemeralKeyPair pair;

    crypto_kx_keypair(
        pair.publicKey.data(),
        pair.privateKey.data());

    return pair;
}

const CryptoContext::Key&
CryptoContext::privateKey() const noexcept
{
    return privateKey_;
}


CryptoContext::SessionKeys
CryptoContext::deriveClientSessionKeysEphemeral(
    const Key& serverStatic,
    const Key& serverEphemeral,
    const EphemeralKeyPair& localEphemeral) const
{
    unsigned char dh1[32];
    unsigned char dh2[32];
    unsigned char dh3[32];
    unsigned char dh4[32];

    if (
        crypto_scalarmult(
            dh1,
            privateKey_.data(),
            serverStatic.data()) != 0)
    {
        throw std::runtime_error("dh1 failed");
    }

    if (
        crypto_scalarmult(
            dh2,
            localEphemeral.privateKey.data(),
            serverStatic.data()) != 0)
    {
        throw std::runtime_error("dh2 failed");
    }

    if (
        crypto_scalarmult(
            dh3,
            privateKey_.data(),
            serverEphemeral.data()) != 0)
    {
        throw std::runtime_error("dh3 failed");
    }

    if (
        crypto_scalarmult(
            dh4,
            localEphemeral.privateKey.data(),
            serverEphemeral.data()) != 0)
    {
        throw std::runtime_error("dh4 failed");
    }

    unsigned char keyMaterial[64];

    crypto_generichash_state st;

    crypto_generichash_init(
        &st,
        nullptr,
        0,
        sizeof(keyMaterial));

    crypto_generichash_update(
        &st,
        dh1,
        sizeof(dh1));

    crypto_generichash_update(
        &st,
        dh2,
        sizeof(dh2));

    crypto_generichash_update(
        &st,
        dh3,
        sizeof(dh3));

    crypto_generichash_update(
        &st,
        dh4,
        sizeof(dh4));

    crypto_generichash_final(
        &st,
        keyMaterial,
        sizeof(keyMaterial));

    sodium_memzero(dh1, sizeof(dh1));
    sodium_memzero(dh2, sizeof(dh2));
    sodium_memzero(dh3, sizeof(dh3));
    sodium_memzero(dh4, sizeof(dh4));

    SessionKeys keys;

    memcpy(
        keys.send.data(),
        keyMaterial,
        32);

    memcpy(
        keys.recv.data(),
        keyMaterial + 32,
        32);

    sodium_memzero(
        keyMaterial,
        sizeof(keyMaterial));

    return keys;
}


CryptoContext::SessionKeys
CryptoContext::deriveServerSessionKeysEphemeral(
    const Key& clientStatic,
    const Key& clientEphemeral,
    const EphemeralKeyPair& serverEphemeral) const
{
    unsigned char dh1[32];
    unsigned char dh2[32];
    unsigned char dh3[32];
    unsigned char dh4[32];

    /*
     * DH1:
     * server static private
     * x
     * client static public
     */
    if (
        crypto_scalarmult(
            dh1,
            privateKey_.data(),
            clientStatic.data()) != 0)
    {
        throw std::runtime_error(
            "server dh1 failed");
    }

    /*
     * DH2:
     * server static private
     * x
     * client ephemeral public
     */
    if (
        crypto_scalarmult(
            dh2,
            privateKey_.data(),
            clientEphemeral.data()) != 0)
    {
        throw std::runtime_error(
            "server dh2 failed");
    }

    /*
     * DH3:
     * server ephemeral private
     * x
     * client static public
     */
    if (
        crypto_scalarmult(
            dh3,
            serverEphemeral.privateKey.data(),
            clientStatic.data()) != 0)
    {
        throw std::runtime_error(
            "server dh3 failed");
    }

    /*
     * DH4:
     * server ephemeral private
     * x
     * client ephemeral public
     */
    if (
        crypto_scalarmult(
            dh4,
            serverEphemeral.privateKey.data(),
            clientEphemeral.data()) != 0)
    {
        throw std::runtime_error(
            "server dh4 failed");
    }

    unsigned char keyMaterial[64];

    crypto_generichash_state st;

    crypto_generichash_init(
        &st,
        nullptr,
        0,
        sizeof(keyMaterial));

    crypto_generichash_update(
        &st,
        dh1,
        sizeof(dh1));

    crypto_generichash_update(
        &st,
        dh2,
        sizeof(dh2));

    crypto_generichash_update(
        &st,
        dh3,
        sizeof(dh3));

    crypto_generichash_update(
        &st,
        dh4,
        sizeof(dh4));

    crypto_generichash_final(
        &st,
        keyMaterial,
        sizeof(keyMaterial));

    sodium_memzero(
        dh1,
        sizeof(dh1));

    sodium_memzero(
        dh2,
        sizeof(dh2));

    sodium_memzero(
        dh3,
        sizeof(dh3));

    sodium_memzero(
        dh4,
        sizeof(dh4));

    SessionKeys keys;

    /*
     * Reverse direction from client.
     *
     * Client:
     *   send = first 32
     *   recv = second 32
     *
     * Server:
     *   recv = first 32
     *   send = second 32
     */

    memcpy(
        keys.recv.data(),
        keyMaterial,
        32);

    memcpy(
        keys.send.data(),
        keyMaterial + 32,
        32);

    sodium_memzero(
        keyMaterial,
        sizeof(keyMaterial));

    return keys;
}