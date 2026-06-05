#pragma once

#include <stdint.h>
#include <sodium.h>

#include <arpa/inet.h>

#include <sys/select.h>

#include <unistd.h>

#include <stdio.h>
#include <string>
#include <netinet/ip.h>
#include <netdb.h>
#include "../crypto/crypto.h"
#include "../peer/peer.h"

#define PACKET_HANDSHAKE_INIT 1
#define PACKET_HANDSHAKE_RESP 2
#define PACKET_DATA           3

#define KEY_LEN 32
#define SESSION_KEY_LEN 32
#define NONCE_LEN crypto_secretbox_NONCEBYTES

#define MAX_PACKET_SIZE 2048
#define MAX_PAYLOAD_SIZE 1500

#define SERVER_HOSTNAME "vpn-server"


extern bool handshake_complete;



extern int tun_fd;
extern int udp_fd;


struct handshake_init_t
{
    uint8_t type;

    uint8_t client_public_key[KEY_LEN];
};


typedef struct
{
    uint8_t type;

    uint8_t server_public_key[KEY_LEN];

    uint32_t client_ip;

    uint32_t server_ip;

    uint8_t prefix_len;

} handshake_response_t;




#pragma pack(push,1)

struct data_packet_t
{
    uint8_t type;
    uint64_t nonce;
    uint16_t data_len;

    uint8_t ciphertext[
        MAX_PAYLOAD_SIZE +
        crypto_secretbox_MACBYTES];
};

#pragma pack(pop)



void process_handshake_init(
    uint8_t *buffer,
    struct sockaddr_in *client_addr);

void process_transport_data(
    uint8_t *buffer,
    int len,
    struct sockaddr_in *addr);


void process_transport_client_data(
    uint8_t recv_key[SESSION_KEY_LEN],
    int tun_fd, uint8_t buffer[MAX_PACKET_SIZE]);


void process_tun_packet();

void process_tun_client_packet(
    struct sockaddr_in *server,
    uint64_t &send_nonce,
    uint8_t send_key[SESSION_KEY_LEN],
    int udp_fd);