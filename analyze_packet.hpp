#ifndef ANALYZE_PACKET_HPP
#define ANALYZE_PACKET_HPP

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <map>

struct ping_packet
{
// IP header
    uint8_t  ihl_version;
    uint8_t  service_type;
    uint16_t length;
    uint16_t id;
    uint16_t flags;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t ip_checksum;
    uint32_t source_ip;
    uint32_t destination_ip;
// ICMP header
    uint8_t  icmp_message_type;
    uint8_t  icmp_code;
    uint16_t icmp_checksum;
    uint32_t icmp_header_data;
    uint8_t* icmp_payload; // Указатель на данные поля “Полезная нагрузка ICMP”, рис. 1
// Полезную нагрузку не копировать, просто поставить сюда адрес из буфера buffer где она начинается
    uint16_t icmp_payload_length; // Здесь должна быть длина в байтах поля “Полезная нагрузка ICMP”, рис. 1, её требуется посчитать
};

void init_packet_analyzer();

void fill_ping_packet_structure( uint8_t* ping_buffer, struct ping_packet * ping_structure );
bool analyze_packet(uint8_t* buffer, int length);

#endif // ANALYZE_PACKET_HPP
