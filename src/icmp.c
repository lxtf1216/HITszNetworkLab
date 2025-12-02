#include "icmp.h"

#include "ip.h"
#include "net.h"
#define ICMP_HD_LEN 8
#define ICMP_CPY_LEN 8
/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    printf("hajimi\n");
    // TO-DO
    buf_t txbuf;
    int req_len = req_buf->len;

    if(req_len < ICMP_HD_LEN) 
        return ;
    
    int payload_len = req_len - ICMP_HD_LEN;
    int resp_len = req_len;

    buf_init(&txbuf,resp_len);

    icmp_hdr_t *req_hdr = (icmp_hdr_t *)req_buf->data;
    icmp_hdr_t *resp_hdr = (icmp_hdr_t *)txbuf.data;

    resp_hdr->code = 0;
    resp_hdr->id16 = req_hdr->id16;
    resp_hdr->seq16 = req_hdr->seq16;
    resp_hdr->type = ICMP_TYPE_ECHO_REPLY;

    if(payload_len>0){
         memcpy((uint8_t *)txbuf.data + ICMP_HD_LEN,
               (uint8_t *)req_buf->data + ICMP_HD_LEN,
               payload_len);
    }
    txbuf.len = resp_len;
    
    resp_hdr->checksum16 = 0;
    resp_hdr->checksum16 = swap16(checksum16((uint16_t *)txbuf.data,txbuf.len));

    ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    printf("\nnow!!! icmp in!!!\n");
    // TO-DO
    if(buf->len < ICMP_HD_LEN) {
        return ;
    }
    icmp_hdr_t *hdr = (icmp_hdr_t *)(buf->data);

    //checksum

    if(checksum16((uint16_t *)buf->data,buf->len)!=0) return ;
    if(hdr->type == ICMP_TYPE_ECHO_REQUEST && hdr->code ==0) {
        icmp_resp(buf,src_ip);
    }
}


/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    printf("\nnow!!!,icmp unr!!!\n");
    // TO-DO
    if(!recv_buf || !src_ip) return ;

    if(recv_buf->len < 20) {
        return ;
    }
    uint8_t * orig_pkt = recv_buf->data;
    uint8_t ihl = orig_pkt[0] & 0x0f;
    int orig_ihl_bytes = ihl*4;
    if (orig_ihl_bytes < 20) orig_ihl_bytes = 20;

    int copy_payload_bytes = 8;
    int available_after_ihl = recv_buf->len - orig_ihl_bytes;
    if (available_after_ihl < 0) available_after_ihl = 0;
    if (available_after_ihl < copy_payload_bytes) copy_payload_bytes = available_after_ihl;


    buf_t txbuf;
    int total_icmp_len = ICMP_HD_LEN + orig_ihl_bytes+ ICMP_CPY_LEN;
    buf_init(&txbuf, total_icmp_len);

    icmp_hdr_t *icmp = (icmp_hdr_t *)txbuf.data;
    icmp->type = ICMP_TYPE_UNREACH; 
    icmp->code = (uint8_t)code;          
    icmp->checksum16 = 0;
    icmp->seq16 = 0;
    icmp->id16 = 0;

    uint8_t *icmp_data_ptr = (uint8_t *)txbuf.data + ICMP_HD_LEN;

    memcpy(icmp_data_ptr,orig_pkt,orig_ihl_bytes);
    if(copy_payload_bytes > 0) {
        memcpy(icmp_data_ptr+orig_ihl_bytes,
            orig_pkt+orig_ihl_bytes,
            copy_payload_bytes
        );
        if(copy_payload_bytes < ICMP_CPY_LEN) 
            memset(icmp_data_ptr+orig_ihl_bytes+copy_payload_bytes,0,ICMP_CPY_LEN-copy_payload_bytes);
    }
    txbuf.len = total_icmp_len;

    icmp->checksum16 = swap16(checksum16((uint16_t *)txbuf.data,txbuf.len));

    ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}