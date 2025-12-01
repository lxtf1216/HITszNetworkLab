#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // TO-DO
     // Step1: 数据长度检查
    // 至少要能容纳一个完整的以太网头部（14字节）
    if (buf->len < sizeof(ether_hdr_t)) {
        // 数据包不完整，丢弃
        return;
    }

    // 获取以太网头部
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    // 进一步校验目的MAC是否匹配本机或广播地址
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t my_mac[6] = NET_IF_MAC;

    int is_to_me = 1;
    for (int i = 0; i < 6; i++) {
        if (hdr->dst[i] != my_mac[i]) {
            is_to_me = 0;
            break;
        }
    }
    int is_broadcast = 1;
    for (int i = 0; i < 6; i++) {
        if (hdr->dst[i] != broadcast_mac[i]) {
            is_broadcast = 0;
            break;
        }
    }

    if (!is_to_me && !is_broadcast) {
        // 不是发给本机也不是广播，丢弃
        return;
    }

    // Step2: 移除以太网包头
    buf_remove_header(buf, sizeof(ether_hdr_t));

    // Step3: 向上层传递数据包
    net_in(buf, swap16(hdr->protocol16), hdr->src);  // 协议字段转为主机字节序
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
     //Step1: 数据长度检查与填充
    //以太网最小帧数据部分为46字节，若不足则填充
    if (buf->len < 46) {
        buf_add_padding(buf, 46-buf->len);
    }

    // Step2: 添加以太网包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    // Step3: 填写目的MAC地址
    for (int i = 0; i < NET_MAC_LEN; i++) {
        hdr->dst[i] = mac[i];
    }

    // Step4: 填写源MAC地址（本机MAC）
    uint8_t my_mac[6] = NET_IF_MAC;
    for (int i = 0; i < NET_MAC_LEN; i++) {
        hdr->src[i] = my_mac[i];
    }

    // Step5: 填写协议类型（需转换为网络字节序）
    hdr->protocol16 = swap16(protocol);  // 假设有 swap16 处理大小端

    // Step6: 发送数据帧
     driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
