#include "analyze_packet.hpp"
#include "config.hpp"
#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <iostream>
#include <chrono>
#include "icmp_payloads.hpp"

using namespace std;

/// Таблица с информацией о количестве принятых и переданных пакетов

map<uint32_t,map<uint32_t,uint32_t>> packetsTable;

/// Таблица с информацией о заблокированных адресах(пара адресов - адрес источника - адрес назначения )

map<uint32_t,map<uint32_t,uint32_t>> blockedPacketsTable;

/// Мьютекс использующийся для блокировки доступа к таблице packetsTable и blockedPacketsTable
///  Нужен чтобы избежать ситуации одновременного доступа к таблице packetsTable и blockedPacketsTable из двух мест

std::mutex packetsTableMutex;

/// Дескриптор файла, в который выводится информация

FILE *fileForErrorData = 0;

/**
 *
 * @brief Выводит сообщение об аномальном траффике на терминал, также дублирует это сообщение в файл
 *
 * @param source_ip      - адрес(в виде числа) источника аномального трафиика
 * @param destination_ip - адрес(в види числа) назначения аномального трафика
 * @param error_reason   - строка с причиной ошибки
 *
 */

void showAndSaveErrorMessage(uint32_t source_ip, uint32_t destination_ip, const char* error_reason )
{

    static const char errorReasonTemplate[] = "Reason: %s\n\n";
    static const char errorHeaderTemplate[] = "Anomaly traffic detected from IP : %d.%d.%d.%d at %s \n";

    time_t rawtime;
    struct tm * timeinfo;

    time (&rawtime);
    timeinfo = localtime (&rawtime);

    char currentTime [80];

    strftime (currentTime,80,"%d/%m/%y %H:%M:%S ",timeinfo);

    printf(errorHeaderTemplate, source_ip >> 24, (source_ip >> 16) & 0xFF, (source_ip >> 8) & 0xFF, source_ip & 0xFF, currentTime );
    printf(errorReasonTemplate, error_reason );

    fprintf(fileForErrorData, errorHeaderTemplate, source_ip >> 24, (source_ip >> 16) & 0xFF, (source_ip >> 8) & 0xFF, source_ip & 0xFF, currentTime );
    fprintf(fileForErrorData, errorReasonTemplate, error_reason );

    fflush(NULL);

    fflush(fileForErrorData);

}

/**
 *
 * @brief Вспомогательная фукнция, преобразует IP адрес записанный в виде чила в строку
 *
 * @param ipValue - значение адреса в виде числа
 *
 * @return строка с адресом
 *
 */

string getStringFromIp(uint32_t ipValue)
{

    return std::to_string( (ipValue >> 24) & 0xFF ) + "." + std::to_string( (ipValue >> 16) & 0xFF ) + "." +  std::to_string((ipValue >> 8) & 0xFF)  + "." +  std::to_string(ipValue & 0xFF);

}

/**
 *
 * @brief Функция которая запускается в отдельном потоке. Она раз в 3 секунды проверяет количество пакетов, если оно было превышено,
 *         то производит действия
 *
 */

void checkPacketsThread()
{

    while(1)
    {

        packetsTableMutex.lock();

        // -------

        for(map<uint32_t,map<uint32_t,uint32_t>>::iterator it = packetsTable.begin(); it != packetsTable.end(); ++it)
        {

            for( map<uint32_t,uint32_t>::iterator sit = it->second.begin(); sit != it->second.end(); ++sit )
            {


                // cout << "Entry - " << getStringFromIp(it->first) << " <--> " << getStringFromIp(sit->first) << " count - " << sit->second << "\n";

                if( sit->second > ANOMALY_PACKET_COUNT )
                {

                    showAndSaveErrorMessage(it->first, sit->first, "Too many packets at time");

                    blockedPacketsTable[it->first][sit->first] = 1;

                }

                // Адрес источника --- getStringFromIp(it->first)
                // Адрес назначения --- getStringFromIp(sit->first)
                // Количество пакетов --- sit->second

            }

        }

        packetsTable.clear();

        packetsTableMutex.unlock();

        // -------

        this_thread::sleep_for(std::chrono::seconds(CHECK_PACKET_INTERVAL_IN_SECONDS));

    }

}

/**
 *
 * @brief Вспомогательная фукнция, заполняет поля структуры ping_packet по данным из буфера ping_buffer
 *
 * @param ping_buffer    - буфер с данными ICMP пакета
 * @param ping_structure - структура в которую будут записанны(скопированы) данные из ICMP пакета
 *
 */

void fill_ping_packet_structure( uint8_t* ping_buffer, struct ping_packet * ping_structure )
{
    ping_structure->ihl_version = ping_buffer[0];
    ping_structure->service_type = ping_buffer[1];

    ping_structure->length = ping_buffer[2]; ping_structure->length <<= 8; ping_structure->length = ping_buffer[3];

    // ping_structure->length = ( ( (uint16_t) ping_buffer[2] ) << 8 ) | ping_buffer[3];

    ping_structure->id = ( ( (uint16_t) ping_buffer[4] ) << 8 ) | ping_buffer[5];

    ping_structure->flags = ( ( (uint16_t) ping_buffer[6] ) << 8 ) | ping_buffer[7];

    ping_structure->ttl = ping_buffer[8];

    ping_structure->protocol = ping_buffer[9];

    ping_structure-> ip_checksum = ( ( (uint16_t) ping_buffer[10] ) << 8 ) | ping_buffer[11];

    ping_structure -> source_ip = ((uint32_t) ping_buffer[12] << 24) | (((uint32_t)ping_buffer[13]) << 16);
    ping_structure->source_ip |= (((uint16_t)ping_buffer[14] << 8) | ping_buffer[15]);

    ping_structure->destination_ip = ((uint32_t) ping_buffer[16] << 24) | (((uint32_t)ping_buffer[17]) << 16);
    ping_structure->destination_ip |= (((uint16_t)ping_buffer[18] << 8) | ping_buffer[19]);

    ping_structure->icmp_message_type = ping_buffer[20];
    ping_structure->icmp_code = ping_buffer[21];
    ping_structure->icmp_checksum = (((uint16_t)ping_buffer[22]) << 8) | ping_buffer[23];

    ping_structure->icmp_header_data = ((uint32_t) ping_buffer[24] << 24) | (((uint32_t)ping_buffer[25]) << 16);
    ping_structure->icmp_header_data = (((uint16_t)ping_buffer[26] << 8) | ping_buffer[27]);

    ping_structure->icmp_payload_length = ping_structure->length - 28;

    if(ping_structure->icmp_payload_length == 0)
    {
        ping_structure->icmp_payload = 0;
    }
    else
    {
        ping_structure->icmp_payload = &ping_buffer[28];
    }

}

/**
 *
 * @brief Инициализация анализатора пакетов
 *
 */

void init_packet_analyzer()
{

    // Добавляем правила чтобы пакеты попадали в очередь

    // Удаляем правила если оно уже были определены(чтобы не образовывались дубликаты при повторном запуске программы)

    system("iptables -D INPUT -p icmp -j NFQUEUE --queue-num 0");
    system("iptables -D OUTPUT -p icmp -j NFQUEUE --queue-num 0");

    // Добавляем правила

    system("iptables -A INPUT -p icmp -j NFQUEUE --queue-num 0");
    system("iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0");

    // Очищаем таблицы с информацией

    packetsTable.clear();
    blockedPacketsTable.clear();

    // Открываем файл куда будет записываться информация о аномальных пакетах

    fileForErrorData = fopen("fileForErrorData", "a+");

    // Запускаем фукнцию checkPacketsThread как отдельный поток

    // Создаем объект потока, куда передаем фукнцию checkPacketsThread

    thread thr(checkPacketsThread);

    // Запускаем фукнцию checkPacketsThread как отдельный поток
    //  она продолжает работать отдельно от фукнции init_packet_analyzer

    thr.detach();

}

/**
 *
 * @brief Производит анализ пакета по его содежримому
 *         пакет на входе должен начинаться с заголовка IP, MAC заголовок не анализируется!
 *
 * @param buffer - указатель на начало пакета
 * @param length - длина пакета в байтах
 *
 * @return true - пакет можно передавать, false - пакет определен как аномальный, блокировать
 *
 */

bool analyze_packet(uint8_t* buffer, int length)
{

    struct ping_packet packet;

    fill_ping_packet_structure((uint8_t*)buffer,&packet);

     //printf("\nNew packet!, Packet Length : %d \r\n" , packet.length);
     //printf("Packet source IP : %d.%d.%d.%d \r\n" , packet.source_ip >> 24, (packet.source_ip >> 16) & 0xFF, (packet.source_ip >> 8) & 0xFF, packet.source_ip & 0xFF);
     //printf("Packet destination IP : %d.%d.%d.%d \r\n" , packet.destination_ip >> 24, (packet.destination_ip >> 16) & 0xFF, (packet.destination_ip >> 8) & 0xFF, packet.destination_ip & 0xFF);

     //printf("Payload length: %d\r\n", packet.icmp_payload_length);

     // Check packet length

     if(packet.icmp_payload_length > MAXIMUM_ICMP_PAYLOAD_LENGTH )
     {

         showAndSaveErrorMessage(packet.source_ip, packet.destination_ip, "payload length exceed 100 bytes" );

         return 0;

     }

     // Check packet data

     if( (packet.icmp_code == 0) || (packet.icmp_message_type == 8) )
     {

        // 48 linux
        // 32 windows

        if( packet.icmp_payload_length == 32 )
        {
            // Check for windows
            for(int i = 0; i < 32; i++ )
            {
                if(packet.icmp_payload[i] != windows_icmp_data[i])
                {

                    showAndSaveErrorMessage(packet.source_ip, packet.destination_ip, "ICMP payload is illegal" );

                    return 0;

                }
            }
        }
        else if( packet.icmp_payload_length == 56 )
        {
            // Check for linux data
            for(int i = 16; i < 56; i++)
            {
                if(packet.icmp_payload[i] != linux_icmp_data[i-16])
                {

                    showAndSaveErrorMessage(packet.source_ip, packet.destination_ip, "ICMP payload is illegal" );

                    return 0;
                }
            }
        }
        else
        {


            showAndSaveErrorMessage(packet.source_ip, packet.destination_ip, "incorrect ICMP payload length" );

            return 0;

        }
    }
    else
    {

        showAndSaveErrorMessage(packet.source_ip, packet.destination_ip, "ICMP code and message type unallowed" );

        return 0;

    }

    // Записываем в таблицу только пакеты прошедшие проверку на содержимое
    //  Перед этим проверяем был ли ранее заблокирован IP

    packetsTableMutex.lock();

    for(map<uint32_t,map<uint32_t,uint32_t>>::iterator it = blockedPacketsTable.begin(); it != blockedPacketsTable.end(); ++it)
    {
        for( map<uint32_t,uint32_t>::iterator sit = it->second.begin(); sit != it->second.end(); ++sit )
        {
            if( (packet.source_ip == it->first) && (packet.destination_ip == sit->first) )
            {
                // Этот IP был ранее заблокирован!
                showAndSaveErrorMessage(it->first, sit->first, "Ip already blocked by many packet at time");
                packetsTableMutex.unlock();
                return 0;
            }
        }
    }

    // Проверка по IP пройдена записываем адреса для статистики и анализа

    packetsTable[packet.source_ip][packet.destination_ip] += 1;

    packetsTableMutex.unlock();

     // mymap[packet.source_ip][packet.destination_ip] = time(NULL)

     // linux_icmp_data
     // windows_icmp_data

     /*
     for(int i = 0 ; i < packet.icmp_payload_length; i++)
     {
         printf("%x ", packet.icmp_payload[i] );
     }
     */

     return 1;

}
