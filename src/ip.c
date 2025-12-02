#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"
#define IP_MAX_PAYLOAD 1480
#define IP_HEADER_LEN 20
static int next_ip_id = 0;
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    //step1
    if(!buf || !buf->data) return ;
    if(buf->len < sizeof(ip_hdr_t)) return ;

    //step 2
    ip_hdr_t *ip = (ip_hdr_t *)buf->data;
    uint8_t  version =ip->version;
    uint8_t ihl = ip->hdr_len;
    int ip_header_len = ihl * 4;

    if(version != IP_VERSION_4) return ;
    if(ihl < 5) return ;
    uint16_t totlen = swap16(ip->total_len16);
    if(totlen < ip_header_len ) return ;

    if(totlen > buf->len) return ;

    //step 3
    uint16_t orig_checksum = ip->hdr_checksum16;
    uint16_t saved_cksum = orig_checksum;
    ip->hdr_checksum16 = 0;
    uint16_t calc_checksum = checksum16((uint16_t *)ip, ip_header_len);
    ip->hdr_checksum16 = saved_cksum;
    if(calc_checksum ^ orig_checksum) {
        return ;
    }

    //step 4
    if(memcmp(ip->dst_ip,net_if_ip,NET_IP_LEN)!=0) {
        return ;
    }
    //step 5
    if(buf->len > totlen) {
        buf_remove_padding(buf,totlen);
    }

    //step 6
    uint8_t ip_header_backup[60];
    if(ip_header_len > (int)sizeof(ip_header_backup)) {
        return ;
    }
    memcpy(ip_header_backup,buf->data,IP_HEADER_LEN);

    buf_remove_header(buf, ip_header_len);

    int ret = net_in(buf,ip->protocol,ip->src_ip);
    if(ret<0) {
        if(buf_add_header(buf,ip_header_len)==0) {
            memcpy(buf->data,ip_header_backup,ip_header_len);
            icmp_unreachable(buf,ip->src_ip,ICMP_CODE_PROTOCOL_UNREACH);
        } else {
            return ;
        }
    }
    return;
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    //step 1
    if(buf_add_header(buf,IP_HEADER_LEN)!=0) 
        return ;
    
    ip_hdr_t *ip_hdr = (ip_hdr_t* )buf->data;
    uint8_t ihl = IP_HEADER_LEN/4;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = ihl;
    //((uint8_t*)ip_hdr)[0] = 0x45;
    ip_hdr->tos = 0;
    uint16_t total_len = swap16((uint16_t)(buf->len));
    ip_hdr->total_len16 = total_len;

    ip_hdr->id16 = swap16(id);

    uint16_t offset8_units = (uint16_t)((offset/8)&0x1fff);
    uint16_t flags_field = (mf?0x2000:0x0000) | offset8_units;
    ip_hdr->flags_fragment16 = swap16(flags_field);

    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->protocol = (uint8_t)protocol;


    memcpy(ip_hdr->src_ip,net_if_ip,NET_IP_LEN);
    memcpy(ip_hdr->dst_ip,ip,NET_IP_LEN);

    ip_hdr->hdr_checksum16 = 0;
    uint16_t chksum = checksum16((uint16_t *)ip_hdr,IP_HEADER_LEN);
    ip_hdr->hdr_checksum16 = swap16(chksum);

    arp_out(buf,ip);

    return ;
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    //step 1
    uint32_t payload_len = buf->len;

    uint16_t id = next_ip_id++ ;
 
    if(payload_len <= IP_MAX_PAYLOAD) {
        buf_t frag;
        if(buf_init(&frag,payload_len)!=0) return ;
        if (payload_len) memcpy(frag.data, buf->data, payload_len);
        ip_fragment_out(&frag, ip, protocol, id, 0 /*offset*/, 0 /*mf*/);
        //buf_free(&frag);
        return;
    } 
    //printf("wcccccccccc%d\n",payload_len);
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = payload_len;

    while(bytes_remaining>0) {
        uint32_t this_len;
        int mf;
        if(bytes_remaining>IP_MAX_PAYLOAD) {
            this_len = IP_MAX_PAYLOAD;
            mf=1;
        } else {
            this_len = bytes_remaining;
            mf=0;
        }
        buf_t frag;
        //printf("thislen!%d\n",this_len);
        if(buf_init(&frag,(uint16_t)this_len)!=0) {
            return ;
        }
        memcpy(frag.data,buf->data+bytes_sent,this_len);
        ip_fragment_out(&frag,ip,protocol,id,bytes_sent,mf);
        //buf_free(&frag);
        bytes_sent += this_len;
        bytes_remaining -= this_len;
        //printf("now sent%d remain%d\n",bytes_sent,bytes_remaining);
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}