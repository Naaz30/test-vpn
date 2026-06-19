#pragma once

#include <cstdint>
#include <sodium.h>

struct ClientSession;

constexpr uint8_t PACKET_HANDSHAKE_INIT = 1;
constexpr uint8_t PACKET_HANDSHAKE_RESP = 2;
constexpr uint8_t PACKET_DATA = 3;

constexpr std::size_t MAX_PACKET_SIZE = 2048;
constexpr std::size_t MAX_PAYLOAD_SIZE = 1500;

constexpr const char* SERVER_HOSTNAME = "vpn-server";



#pragma pack(push,1)
struct handshake_init_t
{
    uint8_t type;

    uint32_t index;

    uint64_t epoch_ts;

    uint8_t client_static_public_key[KEY_LEN];

    uint8_t client_ephemeral_public_key[KEY_LEN];
};
#pragma pack(pop)


#pragma pack(push,1)
struct handshake_response_t
{
    uint8_t type;

    uint8_t server_static_public_key[KEY_LEN];

    uint8_t server_ephemeral_public_key[KEY_LEN];

    uint32_t client_ip;
    uint32_t server_ip;

    uint8_t prefix_len;

    uint32_t index;
};
#pragma pack(pop)


#pragma pack(push,1)
struct data_packet_t
{
    uint8_t type;
    uint64_t nonce;
    uint16_t data_len;
    uint32_t index;

    uint8_t ciphertext[
        MAX_PAYLOAD_SIZE +
        crypto_secretbox_MACBYTES];
};
#pragma pack(pop)


void process_transport_client_data(
    ClientSession& session,
    const uint8_t* buffer);

void process_tun_client_packet(
    ClientSession& session);

