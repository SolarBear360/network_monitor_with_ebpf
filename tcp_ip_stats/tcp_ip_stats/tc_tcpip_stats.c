//==============================================
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define BPF_NO_PRESERVE_ACCESS_INDEX

// TC actions
#define TC_ACT_OK 0

// Ethernet protocol
#define ETH_P_IP   0x0800
#define IPPROTO_TCP  6

// Address family
#define AF_INET   2
#define AF_INET6 10

#define BUCKET_NS 1000000000ULL  // 1 秒
#define NUM_BUCKETS 64

/*
 * TCP connection state
 */
#define TCP_STATE_UNKNOWN       0
#define TCP_STATE_SYN_SENT      1
#define TCP_STATE_SYN_RECEIVED  2
#define TCP_STATE_ESTABLISHED   3

struct tcp_flow_key {
    __u32 src_ip;
    __u32 dst_ip;

    __u16 src_port;
    __u16 dst_port;

    __u8  protocol;

    // padding，讓 struct 對齊
    __u8  pad[3];
};


/*
 * 每一個 TCP flow 的統計資料
 */
struct tcp_flow_stats {
    __u64 packets;
    __u64 bytes;

    /*
     * 只統計握手階段的 SYN / ACK
     *
     * SYN:
     *   SYN=1 ACK=0
     *   SYN=1 ACK=1
     *
     * ACK:
     *   只統計 SYN+ACK
     *
     *   不統計：
     *   SYN=0 ACK=1
     */
    __u64 syn;
    __u64 ack;

    __u8 connection_state;

    /*
     * padding
     *
     * 因為後面沒有其他欄位，
     * 這裡不需要特別補到 8 bytes。
     */
    __u8 pad[7];

    __u64 first_seen;
    __u64 last_seen;
};


// ========================
// ① 主統計 map（不變）
// ========================
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct tcp_flow_key);
    __type(value, struct tcp_flow_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_flow_map SEC(".maps");

// ========================
// ③ bucket array（queue）
// ========================
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, NUM_BUCKETS);
    __type(key, __u32);

    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct  {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 4096);
        __type(key, struct tcp_flow_key);
        __type(value, __u8);
    });
} tcp_bucket_maps SEC(".maps");


// ========================
// ④ current bucket index
// ========================
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_current_bucket SEC(".maps");

SEC("tc")
int tc_tcp_flow(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /*
     * ========================================
     * Ethernet
     * ========================================
     */

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;


    /*
     * 只處理 IPv4
     */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;


    /*
     * ========================================
     * IPv4
     * ========================================
     */

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;


    /*
     * 只處理 TCP
     */
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;


    /*
     * IPv4 header 長度
     *
     * ihl 的單位是 32-bit word
     */
    __u32 ip_header_len = ip->ihl * 4;

    if (ip_header_len < sizeof(struct iphdr))
        return TC_ACT_OK;

    if ((void *)ip + ip_header_len > data_end)
        return TC_ACT_OK;


    /*
     * ========================================
     * TCP
     * ========================================
     */

    struct tcphdr *tcp =
        (void *)ip + ip_header_len;

    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    //----------- debug --------------------
    unsigned char s[4], d[4];
    s[0] = ip->saddr & 0xFF; s[1] = (ip->saddr >> 8) & 0xFF; s[2] = (ip->saddr >> 16) & 0xFF; s[3] = (ip->saddr >> 24) & 0xFF;
    d[0] = ip->daddr & 0xFF; d[1] = (ip->daddr >> 8) & 0xFF; d[2] = (ip->daddr >> 16) & 0xFF; d[3] = (ip->daddr >> 24) & 0xFF;

    bpf_printk("TC [IPv4]: %d.%d.%d.%d -> %d.%d.%d.%d\n",
                   s[0], s[1], s[2], s[3],
                   d[0], d[1], d[2], d[3]);
    bpf_printk("syn : %d, ack : %d\n",tcp->syn,tcp->ack);
    //----------- debug --------------------

    /*
     * ========================================
     * 建立 flow key
     * ========================================
     */
    struct tcp_flow_key key = {};

    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;

    key.src_port = tcp->source;
    key.dst_port = tcp->dest;

    key.protocol = IPPROTO_TCP;

    // ---------- 計算 bucket ----------
    __u64 now = bpf_ktime_get_ns();
    __u32 bucket = (now / BUCKET_NS) % NUM_BUCKETS;

    // 更新 current bucket
    __u32 idx0 = 0;
    bpf_map_update_elem(&tcp_current_bucket, &idx0, &bucket, BPF_ANY);

    /*
     * ========================================
     * 取得 TCP flags
     * ========================================
     */

    __u8 syn = tcp->syn;
    __u8 ack = tcp->ack;


    /*
     * ========================================
     * 查詢 flow
     * ========================================
     */

    struct tcp_flow_stats *stats;

    stats = bpf_map_lookup_elem(
        &tcp_flow_map,
        &key
    );

    /*
     * ========================================
     * 第一次看到這個 flow
     * ========================================
     */

    if (!stats) {
        bpf_printk("---------------stats---------------\n");
        struct tcp_flow_stats new_stats = {};

        /*
         * 所有 TCP 封包都計算
         */
        new_stats.packets = 1;
        new_stats.bytes = skb->len;


        /*
         * ====================================
         * SYN / ACK 統計
         * ====================================
         *
         * SYN=1 ACK=0
         *     → SYN++
         *
         * SYN=1 ACK=1
         *     → SYN++
         *     → ACK++
         *
         * SYN=0 ACK=1
         *     → 不增加 ACK
         */

        if (syn) {
            new_stats.syn++;
        }

        if (syn && ack) {
            new_stats.ack++;
        }


        /*
         * ====================================
         * connection state
         * ====================================
         */

        if (syn && !ack) {

            /*
             * SYN
             */
            new_stats.connection_state =
                TCP_STATE_SYN_SENT;

        }
        else if (syn && ack) {

            /*
             * SYN + ACK
             */
            new_stats.connection_state =
                TCP_STATE_SYN_RECEIVED;

        }
        else {

            /*
             * 如果第一個看到的封包不是
             * SYN / SYN+ACK，
             * 無法確定握手狀態。
             */
            new_stats.connection_state =
                TCP_STATE_UNKNOWN;
        }


        /*
         * ====================================
         * 時間
         * ====================================
         */

        new_stats.first_seen = now;
        new_stats.last_seen = now;

        // ---------- 寫入 bucket map ----------
        // 看當前的bucket 有沒有這個key，沒有則將這個key寫進去。
        // 例: 連續兩秒寫入封包，上一個bucket和下一個bucket都會有這個key
        // tcp_stats_map則會記錄last_seen
        void *inner_map = bpf_map_lookup_elem(&tcp_bucket_maps, &bucket);

        if (!inner_map) {
            bpf_printk("inner_map is NULL!\n");
        }
        
        if (inner_map) {
            __u8 one = 1;
            bpf_printk("into bucket: %p \n",bucket);
            // 用 NOEXIST → 避免重複寫入（變 set）
            bpf_map_update_elem(inner_map, &key, &one, BPF_NOEXIST);
        }

        /*
         * ====================================
         * 插入 map
         * ====================================
         */

        bpf_map_update_elem(
            &tcp_flow_map,
            &key,
            &new_stats,
            BPF_ANY
        );

        return TC_ACT_OK;
    }
    /*
        * ========================================
        * 已經存在的 flow
        * ========================================
        */

        /*
        * 所有 TCP 封包都統計
        */
        stats->packets++;
        stats->bytes += skb->len;


        /*
        * ========================================
        * SYN / ACK / connection state
        * ========================================
        */

        if (syn && !ack) {

            /*
            * SYN
            *
            * SYN=1 ACK=0
            */
            stats->syn++;

            stats->connection_state = TCP_STATE_SYN_SENT;
        }
        else if (syn && ack) {

            /*
            * SYN + ACK
            *
            * SYN=1 ACK=1
            */
            stats->syn++;
            stats->ack++;

            stats->connection_state =
                TCP_STATE_SYN_RECEIVED;
        }
        else if (!syn && ack) {

            /*
            * 第三次握手：
            *
            * SYN=0 ACK=1
            *
            * 只改變 connection_state
            *
            * 不：
            *     stats->ack++;
            */

            stats->connection_state =
                TCP_STATE_ESTABLISHED;
        }


        /*
        * ========================================
        * 更新最後看到時間
        * ========================================
        */

        stats->last_seen = now;


        return TC_ACT_OK;


}

char _license[] SEC("license") = "GPL";