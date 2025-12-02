#include "udp.h"

#include "icmp.h"
#include "ip.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;
static inline uint16_t swap16_safe(uint16_t x) {
    return (uint16_t)((x << 8) | (x >> 8));
}

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
   // printf("ok,are we in udp?\n");
    if(!buf || buf->len < sizeof(udp_hdr_t) ) return;
    udp_hdr_t *udph = (udp_hdr_t *)buf->data;

    uint16_t udp_len = swap16(udph->total_len16);
    if(udp_len <sizeof(udp_hdr_t)) {
        return ;
    }

    if((uint16_t)buf->len < udp_len) return ;

    uint16_t old = udph->checksum16;
    udph->checksum16 = 0;
    uint16_t cs = transport_checksum(NET_PROTOCOL_UDP,buf,src_ip,net_if_ip);
    udph->checksum16 = old;
   // printf("udp:now check sum!old%04X cs%04X\n",old,cs);
    if(old!=0 && (old != cs)) return ;
    //printf("udp:check sum ok\n");
    uint16_t dst_port = swap16(udph->dst_port16);
    uint16_t src_port = swap16(udph->src_port16);

    udp_handler_t* handler = (udp_handler_t*)map_get(&udp_table,&dst_port);

    if(!handler) {
        if(!buf_add_header(buf,sizeof(ip_hdr_t))) {
            return ;
        }
        icmp_unreachable(buf,src_ip,ICMP_CODE_PORT_UNREACH);
        return ;
    }
    if(buf_remove_header(buf,sizeof(udp_hdr_t))!=0) {
        return ;
    }
    (*handler)(buf->data,buf->len,src_ip,src_port);
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // TO-DO
    if(!buf) return ;
    if(buf_add_header(buf,sizeof(udp_hdr_t))!=0) return ;
    printf("wcc!!!!\n");
    udp_hdr_t *udph = (udp_hdr_t *)buf->data;
    udph->src_port16 = swap16(src_port);
    udph->dst_port16 = swap16(dst_port);

    udph->total_len16 = swap16((uint16_t)buf->len);

    udph->checksum16 = 0;
    uint16_t cs = transport_checksum(NET_PROTOCOL_UDP,buf,net_if_ip,dst_ip);

    if(cs) {
        udph->checksum16 = swap16(0xffff);
    } else {
        udph->checksum16 = cs;
    }
    ip_out(buf,dst_ip,NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}