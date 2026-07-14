#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define BPF_NO_PRESERVE_ACCESS_INDEX
#ifndef BPF_MAP_TYPE_PERCPU_LRU_HASH
#define BPF_MAP_TYPE_PERCPU_LRU_HASH 27
#endif

// TC actions
#define TC_ACT_OK 0

// Ethernet protocol
#define ETH_P_IP   0x0800   // IPv4
#define ETH_P_IPV6 0x86DD   // IPv6

// Address family
#define AF_INET   2
#define AF_INET6 10

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define BUCKET_NS 10000000000ULL  // 10 秒

struct ip_key {
    __u32 family; // AF_INET (IPv4) 或 AF_INET6 (IPv6)
    union {
        __u32 v4;
        __u32 v6[4]; // 128-bit IPv6 地址
    } ip;
};

struct stats {
    __u64 packets;
    __u64 bytes;
};

// 使用 PERCPU，避免多核心爭搶同一個計數器造成的效能瓶頸
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10000);             // 根據上方表格調整大小
    __type(key, struct ip_key);             // 上面定義的 IP 結構
    __type(value, struct stats);    // 上面定義的統計結構
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct ip_key);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_time_map SEC(".maps");

// 輔助核心計數函式
static __always_inline __u32 count_traffic(struct ip_key *key, struct __sk_buff *skb) {
    struct stats zero = {};
    struct stats *value;

    value = bpf_map_lookup_elem(&ip_stats_map, key);

    if (!value) {
        int ret = bpf_map_update_elem(&ip_stats_map, key, &zero, BPF_NOEXIST);

        if (ret < 0) {
            // map 滿 → 忽略新 IP
            return TC_ACT_OK;
        }

        value = bpf_map_lookup_elem(&ip_stats_map, key);
        if (!value)
            return TC_ACT_OK;
    }

    __u64 now = bpf_ktime_get_ns();
    __u32 bucket = now / BUCKET_NS;

    value->packets += 1;
    value->bytes += skb->len;

    bpf_map_update_elem(&ip_time_map, key, &bucket, BPF_ANY);

    return TC_ACT_OK;
}

// 入口一：專門給 Ingress 掛載
SEC("tc_ingress")
int tc_handle_ingress(struct __sk_buff *skb) {
    return TC_ACT_OK;
}

// 入口二：專門給 Egress 掛載
SEC("tc_egress")
int tc_handle_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 1. 解析 L2 乙太網路標頭
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    __u16 proto = bpf_ntohs(eth->h_proto);

    // 2. 處理 IPv4 封包
    if (proto == ETH_P_IP) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void *)(iph + 1) > data_end) 
            return TC_ACT_OK;

        struct ip_key key = {};
        key.family = AF_INET;
        key.ip.v4 = iph->saddr;

        return count_traffic(&key, skb);
    }
    // 3. 處理 IPv6 封包
    else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if ((void *)(ip6h + 1) > data_end) 
            return TC_ACT_OK;

        struct ip_key key = {};
        key.family = AF_INET6;
        __builtin_memcpy(key.ip.v6, &ip6h->saddr, sizeof(key.ip.v6));

        return count_traffic(&key, skb);
    }


    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";