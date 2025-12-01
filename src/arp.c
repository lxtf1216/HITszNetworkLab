#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // Step1: 初始化缓冲区，分配 ARP 报文所需空间
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // 获取 ARP 报文指针
    arp_pkt_t *arp = (arp_pkt_t *)txbuf.data;

    // Step2: 填写 ARP 报头
    arp->hw_type16 = swap16(ARP_HW_ETHER);        // 以太网硬件类型
    arp->pro_type16 = swap16(NET_PROTOCOL_IP);           // 上层协议为 IP (0x0800)
    arp->hw_len = NET_MAC_LEN;                    // MAC 地址长度 = 6
    arp->pro_len = NET_IP_LEN;                    // IPv4 地址长度 = 4

    // Step3: 设置操作类型为 ARP 请求，并进行大小端转换
    arp->opcode16 = swap16(ARP_REQUEST);

    // 填写发送方信息（本机）
    memcpy(arp->sender_mac, net_if_mac, NET_MAC_LEN);  // 本机 MAC
    memcpy(arp->sender_ip, net_if_ip, NET_IP_LEN);     // 本机 IP

    // 填写目标信息（目标 MAC 未知，置为 0）
    memset(arp->target_mac, 0, NET_MAC_LEN);           // 目标 MAC 为 0
    memcpy(arp->target_ip, target_ip, NET_IP_LEN);     // 目标 IP 为传入参数

    // Step4: 发送 ARP 报文
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ethernet_out(&txbuf, broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    // Step1: 初始化缓冲区，分配 ARP 报文所需空间
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // 获取 ARP 报文指针
    arp_pkt_t *arp = (arp_pkt_t *)txbuf.data;

    // Step2: 填写 ARP 报头
    arp->hw_type16 = swap16(ARP_HW_ETHER);        // 以太网硬件类型
    arp->pro_type16 = swap16(NET_PROTOCOL_IP);    // 上层协议为 IP (0x0800)
    arp->hw_len = NET_MAC_LEN;                    // MAC 地址长度 = 6
    arp->pro_len = NET_IP_LEN;                    // IPv4 地址长度 = 4

    // Step3: 设置操作类型为 ARP 响应，并进行大小端转换
    arp->opcode16 = swap16(ARP_REPLY);

    // 填写发送方信息（本机）
    uint8_t net_if_mac[6] = NET_IF_MAC;
    uint8_t net_if_ip[4] = NET_IF_IP;
    memcpy(arp->sender_mac, net_if_mac, NET_MAC_LEN);  // 本机 MAC
    memcpy(arp->sender_ip, net_if_ip, NET_IP_LEN);     // 本机 IP

    // 填写目标信息（从参数获取）
    memcpy(arp->target_mac, target_mac, NET_MAC_LEN);  // 目标 MAC
    memcpy(arp->target_ip, target_ip, NET_IP_LEN);     // 目标 IP

    // Step4: 单播发送 ARP 响应到目标 MAC
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // Step1: 检查数据长度
    if (buf->len < sizeof(arp_pkt_t)) {
        return;  // 数据包不完整，丢弃
    }

    // 解析 ARP 报文
    arp_pkt_t *arp = (arp_pkt_t *)buf->data;

    // Step2: 报头检查 - 确保报文符合协议规定
    // 检查硬件类型是否为以太网
    if (swap16(arp->hw_type16) != ARP_HW_ETHER) {
        return;
    }
    
    // 检查上层协议类型是否为 IP
    if (swap16(arp->pro_type16) != NET_PROTOCOL_IP) {
        return;
    }
    
    // 检查 MAC 硬件地址长度
    if (arp->hw_len != NET_MAC_LEN) {
        return;
    }
    
    // 检查 IP 协议地址长度
    if (arp->pro_len != NET_IP_LEN) {
        return;
    }
    
    // 检查操作类型是否为 REQUEST 或 REPLY
    uint16_t opcode = swap16(arp->opcode16);
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY) {
        return;
    }

    // Step3: 更新 ARP 表项 - 保持 ARP 表信息最新
    // 无论是请求还是响应，都记录发送方的 IP-MAC 映射
    map_set(&arp_table, arp->sender_ip, arp->sender_mac);

    // Step4: 查看缓存情况
    buf_t *cached_buf = (buf_t *)map_get(&arp_buf, arp->sender_ip);
    
    if (cached_buf != NULL) {
        // 有缓存情况：说明之前发送过 ARP 请求，现在收到了响应
        // 将缓存的数据包发送给以太网层
        ethernet_out(cached_buf, arp->sender_mac, NET_PROTOCOL_IP);
        
        // 删除这个缓存的数据包
        map_delete(&arp_buf, arp->sender_ip);
    } 
    else {
        // 无缓存情况：判断是否为请求本机 MAC 地址的 ARP 请求报文
        
        // 检查是否为 ARP REQUEST 且目标 IP 是本机
        if (opcode == ARP_REQUEST && 
            memcmp(arp->target_ip, net_if_ip, NET_IP_LEN) == 0) {
            // 是请求本主机 MAC 地址的 ARP 请求，回应一个响应报文
            arp_resp(arp->sender_ip, arp->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    uint8_t *mac = (uint8_t *)map_get(&arp_table, ip);

    if (mac != NULL) {
        // Step2: 找到了 MAC 地址，直接发送数据包
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    } 
    else {
        // Step3: 未找到 MAC 地址，需要先发送 ARP 请求
        
        // 检查 arp_buf 中是否已经有针对该 IP 的缓存数据包
        // 使用 map_entry_valid 判断键值对是否存在且有效
        if (map_entry_valid(&arp_buf, ip)) {
            // 已经有包在等待该 IP 的 ARP 响应，不重复发送 ARP 请求
            // 直接返回，等待之前的 ARP 请求得到响应
            return;
        } else {
            // arp_buf 中没有包，说明这是第一次请求该 IP
            // 缓存数据包到 arp_buf
            map_set(&arp_buf, ip, buf);
            // 发送 ARP 请求
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}