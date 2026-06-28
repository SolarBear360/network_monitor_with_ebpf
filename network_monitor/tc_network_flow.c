#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct stats {
    __u32 packets;
    __u32 bytes;
};

// 定義我們傳遞數據的結構體
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2); // 0: 容器出去 (Ingress), 1: 進入容器 (Egress)
    __type(key, __u32);
    __type(value, struct stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_stats_map SEC(".maps");

// 輔助核心計數函式
static __always_inline __u32 count_traffic(__u32 key, struct __sk_buff *skb) {
    struct stats *value = bpf_map_lookup_elem(&pkt_stats_map, &key);

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 1. 解析 L2 乙太網路標頭
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    __u16 proto = bpf_ntohs(eth->h_proto);
    __u32 is_IP = 0;
    // 2. 處理 IPv4 封包
    if (proto == ETH_P_IP) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void *)(iph + 1) > data_end) 
            return TC_ACT_OK;
        is_IP = 1;

        __u32 src_ip = iph->saddr;
        __u32 dest_ip = iph->daddr;

        unsigned char s[4], d[4];
        s[0] = src_ip & 0xFF; s[1] = (src_ip >> 8) & 0xFF; s[2] = (src_ip >> 16) & 0xFF; s[3] = (src_ip >> 24) & 0xFF;
        d[0] = dest_ip & 0xFF; d[1] = (dest_ip >> 8) & 0xFF; d[2] = (dest_ip >> 16) & 0xFF; d[3] = (dest_ip >> 24) & 0xFF;

        bpf_printk("TC [IPv4]: %d.%d.%d.%d -> %d.%d.%d.%d\n",
                   s[0], s[1], s[2], s[3],
                   d[0], d[1], d[2], d[3]);
    }
    // 3. 處理 IPv6 封包
    else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if ((void *)(ip6h + 1) > data_end) 
            return TC_ACT_OK;
        is_IP = 1;
        
        bpf_printk("TC [IPv6]: %pI6 -> %pI6\n", &ip6h->saddr, &ip6h->daddr);
    }

    if (value && is_IP) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, skb->len);
        
        if (key == 0) {
            bpf_printk("[Ingress] Container -> Outside: %u packets\n", value->packets);
        } else {
            bpf_printk("[Egress] Outside -> Container: %u packets\n", value->packets);
        }
        bpf_printk("----------------------------\n");
    }

    return TC_ACT_OK;
}

// 入口一：專門給 Ingress 掛載 (對應原本 batch 檔的 ingress)
SEC("tc_ingress")
int tc_handle_ingress(struct __sk_buff *skb) {
    return count_traffic(0, skb); // 強制給 Key 0
}

// 入口二：專門給 Egress 掛載 (對應原本 batch 檔的 egress)
SEC("tc_egress")
int tc_handle_egress(struct __sk_buff *skb) {
    return count_traffic(1, skb); // 強制給 Key 1
}

/*
SEC("tc")
int tc_count_traffic(struct __sk_buff *skb) {
    __u32 key;
    //ingress，封包從容器出去、送進網卡
    if(skb->ingress_ifindex != 0){
        key = 0;
    }
    //egress，封包從網卡出去、進入容器
    else{
        key = 1;
    }

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 1. 解析 L2 乙太網路標頭
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    __u16 proto = bpf_ntohs(eth->h_proto);
    __u32 is_IP = 0;
    // 2. 處理 IPv4 封包
    if (proto == ETH_P_IP) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void *)(iph + 1) > data_end) 
            return TC_ACT_OK;
        is_IP = 1;

        __u32 src_ip = iph->saddr;
        __u32 dest_ip = iph->daddr;

        unsigned char s[4], d[4];
        s[0] = src_ip & 0xFF; s[1] = (src_ip >> 8) & 0xFF; s[2] = (src_ip >> 16) & 0xFF; s[3] = (src_ip >> 24) & 0xFF;
        d[0] = dest_ip & 0xFF; d[1] = (dest_ip >> 8) & 0xFF; d[2] = (dest_ip >> 16) & 0xFF; d[3] = (dest_ip >> 24) & 0xFF;

        bpf_printk("TC [IPv4]: %d.%d.%d.%d -> %d.%d.%d.%d\n",
                   s[0], s[1], s[2], s[3],
                   d[0], d[1], d[2], d[3]);
    }
    // 3. 處理 IPv6 封包
    else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if ((void *)(ip6h + 1) > data_end) 
            return TC_ACT_OK;
        is_IP = 1;
        // IPv6 位址結構是 s6_addr [16] 字节陣列
        // 為了在 bpf_printk 中印出來，我們將其拆解
        // 註：bpf_printk 的參數有限制（最多5個變數參數），所以我們分兩段印，或是用 %pI6 格式化
        // Linux 核心支援 %pI6 直接印出 IPv6 位址指標！
        
        bpf_printk("TC [IPv6]: %pI6 -> %pI6\n", &ip6h->saddr, &ip6h->daddr);
    }

    
    struct stats *value;

    // 從 Map 中尋找對應的格子
    value = bpf_map_lookup_elem(&pkt_stats_map, &key);
    if (value) {
        // 原子操作（Atomic）累加，避免多核心同時處理封包時發生衝突
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, skb->len);

        bpf_printk("Key [%u] updated: %u packets\n", key, value->packets);
    }

    bpf_printk("----------------------------\n");
    return TC_ACT_OK;
}

*/

char _license[] SEC("license") = "GPL";