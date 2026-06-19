#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

class CryptoContext
{
public:
    static constexpr std::size_t KEY_LEN = 32;
    static constexpr std::size_t SESSION_KEY_LEN = 32;

    using Key = std::array<uint8_t, KEY_LEN>;
    using SessionKey = std::array<uint8_t, SESSION_KEY_LEN>;

    struct EphemeralKeyPair
    {
        Key publicKey;
        Key privateKey;
    };

    struct SessionKeys
    {
        SessionKey send;
        SessionKey recv;
    };

    CryptoContext();
    ~CryptoContext();

    CryptoContext(const CryptoContext &) = delete;
    CryptoContext &operator=(const CryptoContext &) = delete;

    CryptoContext(CryptoContext &&) = delete;
    CryptoContext &operator=(CryptoContext &&) = delete;

    [[nodiscard]]
    EphemeralKeyPair generateEphemeral() const;

    [[nodiscard]]
    const Key &publicKey() const noexcept;

    [[nodiscard]]
    const Key &privateKey() const noexcept;

    [[nodiscard]]
    SessionKeys deriveClientSessionKeys(
        const Key &serverPublicKey) const;

    [[nodiscard]]
    SessionKeys deriveServerSessionKeys(
        const Key &clientPublicKey) const;

    [[nodiscard]]
    SessionKeys deriveClientSessionKeysEphemeral(
        const Key &serverStatic,
        const Key &serverEphemeral,
        const EphemeralKeyPair &localEphemeral) const;

    [[nodiscard]]
    SessionKeys deriveServerSessionKeysEphemeral(
        const Key &clientStatic,
        const Key &clientEphemeral,
        const EphemeralKeyPair &serverEphemeral) const;

private:
    Key publicKey_{};
    Key privateKey_{};
};