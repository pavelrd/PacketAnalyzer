#ifndef CONFIG_HPP
#define CONFIG_HPP

#define MAXIMUM_ICMP_PAYLOAD_LENGTH 100

// Как часто проверять количество принятых/переданных пакетов

#define CHECK_PACKET_INTERVAL_IN_SECONDS 3

// Какое количество ICMP пакетов на один IP адрес в единицу времени CHECK_PACKET_INTERVAL_IN_SECONDS считать аномальным

#define ANOMALY_PACKET_COUNT 10

#endif // CONFIG_HPP
