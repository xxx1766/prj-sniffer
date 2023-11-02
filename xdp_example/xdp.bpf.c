#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define XDP_IPV6 0xdd86
#define XDP_ARP 0x608
#define XDP_PARP 0x538
#define XDP_IP 0x8

SEC("xdp")
int handle_xdp_drop(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    // 检查数据包大小
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;
    int pkt_sz = data_end - data;
    bpf_printk("packet size is %d", pkt_sz);
    //bpf_printk("ethhdr size is %x", sizeof(struct ethhdr));
    //bpf_printk("iphdr size is %x", sizeof(struct iphdr));
    
    // 检查数据包以太网协议
    __u16 h_proto = eth->h_proto;
    // bpf_printk("the packet protocal is %x", h_proto);

    // 检查数据包网络层协议
    if (h_proto == XDP_IPV6){
        bpf_printk("the packet protocal is IPv6");
    }

    if (h_proto == XDP_ARP){
        bpf_printk("the packet protocal is ARP");
    }

    if (h_proto == XDP_PARP){
        bpf_printk("the packet protocal is PARP");
    }

    if (h_proto == XDP_IP){
        // 获取ip头部地址
        struct iphdr *ip = (void*)eth + sizeof(struct ethhdr);
        void* ipend = (void*)ip + sizeof(struct iphdr);
        bpf_printk("the packet protocal is IP");
        // bpf_printk("iphdr %x",eth);
        // bpf_printk("iphdr %x",ip);
        // bpf_printk("iphdr end %x",ipend);
        // bpf_printk("data end %x",data_end);

        if (ipend > data_end) {
            return XDP_DROP;
        }

	    //__u32 daddr = ip->daddr;
        // bpf_printk("ip daddr is %x", daddr);
        // __u32 saddr = ip->saddr;
        __u8 protocol = ip->protocol;
        bpf_printk("ip protocol is %x", protocol);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
