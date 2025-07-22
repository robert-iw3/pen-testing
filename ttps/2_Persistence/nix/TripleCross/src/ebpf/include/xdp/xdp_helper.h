#ifndef __XDP_HELPER_H__
#define __XDP_HELPER_H__

//#include <linux/types.h>
#include "headervmlinux.h"

#include <bpf/bpf_helpers.h>

#include "packet/protocol/ip_helper.h"
#include "packet/protocol/tcp_helper.h"
#include "packet/packet_manager.h"

static struct expand_return{
    int code;
    struct xdp_md *ret_md;
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
}expand_return;

/**
* Increases the packet payload reserved size by more_bytes bytes
* @param ctx XDP hook metadata
* @param eth start of ethernet header. Points inside ctx struct
* @param ip start of internet protocol header. Points inside ctx struct
* @param tcp start of tcp header. Points inside ctx struct
* @param more_bytes Number bytes to add
* @param
*/
static __always_inline struct expand_return expand_tcp_packet_payload(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, int more_bytes){
    //We might be able to reuse some data from old headers,
    //but we will have to recompute checksums still
    struct ethhdr eth_copy;
    struct iphdr ip_copy;
    struct tcphdr tcp_copy;

    struct expand_return ret;

    //Copy the header for later before expanding ctx
    __builtin_memcpy(&eth_copy, eth, sizeof(struct ethhdr));
    __builtin_memcpy(&ip_copy, ip, sizeof(struct iphdr));
    __builtin_memcpy(&tcp_copy, tcp, sizeof(struct tcphdr));

    if (bpf_xdp_adjust_tail(ctx, (int)(sizeof(char)*more_bytes)) != 0){
        //Failed to expand
        bpf_printk("Failed to expand a tcp packet reserved bytes by %i\n", more_bytes);
        ret.code = -1;//The rest is undefined
        return ret; 
    }

    //We must check bounds again, otherwise the verifier gets angry
    ret.eth = (void*)(long)ctx->data;
    ret.ip = (void *)ret.eth + sizeof(struct ethhdr);
    ret.tcp = (void *)ret.ip + sizeof(struct iphdr);
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    if(ethernet_header_bound_check(ret.eth, data_end)<0){
        bpf_printk("Bound check A failed while expanding\n");
        ret.code = -1;//The rest is undefined
        return ret; 
    }

    if (ip_header_bound_check(ret.ip, data_end)<0){
        bpf_printk("Bound check B failed while expanding\n");
        ret.code = -1;//The rest is undefined
        return ret;   
    }

    if (tcp_header_bound_check(ret.tcp, data_end)){
        bpf_printk("Bound check C failed while expanding\n");
        ret.code = -1;//The rest is undefined
        return ret; 
    }

    //We now have to readjust the packet headers, checksums have changed
    //Note that we do not care about ctx->data_meta or any other extra field 
    //since we will not be using any communication here
    __builtin_memcpy((ret.eth), &eth_copy, sizeof(struct ethhdr));
    __builtin_memcpy((ret.ip), &ip_copy, sizeof(struct iphdr));
    __builtin_memcpy((ret.tcp), &tcp_copy, sizeof(struct tcphdr));  
    

    //We modify the fields we care about of the headers
    bpf_printk("before: %i, checksum %u\n", ret.ip->tot_len, ret.ip->check);
    ret.ip->tot_len = bpf_htons(bpf_ntohs(ret.ip->tot_len) + more_bytes);
    __u32 csum = 0;
    ret.ip->check = 0;
	ipv4_csum(ret.ip, sizeof(struct iphdr), &csum);
	ret.ip->check = csum;
    bpf_printk("after: %i, checksum %u\n", ret.ip->tot_len, ret.ip->check);
    ret.ret_md = ctx;
    ret.code = 0;
    ret.data = (void *)(long)ctx->data;
    ret.data_end = (void *)(long)ctx->data_end;
    return ret;
}

static __always_inline void modify_payload(char* payload_org, int payload_size, char* pattern, int pattern_size, void* packet_init, void* packet_limit){
    if(pattern_size > payload_size || pattern_size + (void*)payload_org>packet_limit || payload_size + (void*)payload_org > packet_limit){
        bpf_printk("Invalid attempt to substitute the payload A\n");
        return; //Chicken check
    }

    if((void*)payload_org + pattern_size > (void*)packet_limit){
        bpf_printk("Invalid attempt to substitute the payload B\n");
        return;
    }

    if((void*)payload_org + pattern_size + (payload_size-pattern_size) > (void*)packet_limit){
        bpf_printk("Invalid attempt to substitute the payload C\n");
        return;
    }

    if(payload_size<1 || pattern_size<1){
        bpf_printk("Invalid attempt to substitute the payload D\n");
        return;
    }

    #pragma unroll
    for (int ii=0; ii<pattern_size; ii++){
        payload_org[ii] = pattern[ii];
    }

    
}





#endif