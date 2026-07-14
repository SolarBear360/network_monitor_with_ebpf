# ip紀錄與汰除
待會會用到的定義

- ip資訊(可以為ipv4或v6)
```
struct ip_key {
    __u32 family; // AF_INET (IPv4) 或 AF_INET6 (IPv6)
    union {
        __u32 v4;
        __u32 v6[4]; // 128-bit IPv6 地址
    } ip;
};
```
- 統計數據(包含封包數與總bytes數)
```
struct stats {
    __u64 packets;
    __u64 bytes;
};
```
在bpf中定義hash map，可以藉由**key**來存取**value**

- ip_stats_map是用做儲存特定ip的流量

```
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10000);  // hash map 大小為10000
    __type(key, struct ip_key);  // 使用ip_key結構體作為key
    __type(value, struct stats); // 使用stats結構體作為value
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_stats_map SEC(".maps");
```
- ip_time_map是用做time bucket，用來讓user端的程式可以更快找到一段時間沒傳送封包的ip
```
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct ip_key);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_time_map SEC(".maps");
```
## 主要概念
```
#define BUCKET_NS 10000000000ULL  // 10 秒
.
.
.
__u64 now = bpf_ktime_get_ns(); //開機以來經過的時間(奈秒為單位)
__u32 bucket = now / BUCKET_NS; //開機以來經過的時間(十秒為單位)
```

每次有ip送封包時，將該ip在ip_time_map紀錄的時間改成`bucket`，也就是紀錄該ip最後一次發送封包的時間

- bpf程式部分

```
static __always_inline __u32 count_traffic(struct ip_key *key, struct __sk_buff *skb) {
    struct stats zero = {};
    struct stats *value;
    
//=============== 確認key存不存在map中 ===============
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
//=================================================

    __u64 now = bpf_ktime_get_ns();
    __u32 bucket = now / BUCKET_NS;

    value->packets += 1;
    value->bytes += skb->len;

    //更改紀錄的時間
    bpf_map_update_elem(&ip_time_map, key, &bucket, BPF_ANY);

    return TC_ACT_OK;
}
```

- user端 python程式部分

```
TIMEOUT_BUCKETS = 3 
.
.
.
def main():
    stats_fd = get_map_fd(STATS_MAP_PATH)
    time_fd = get_map_fd(TIME_MAP_PATH)

    while True:
        now_bucket = current_bucket() //計算時間(這裡跟bpf端的算法一樣，每個單位為十秒)

        keys = iterate_keys(time_fd)

        for key in keys:
            last_bucket = lookup_time(time_fd, key)

            if last_bucket is None:
                continue

            # 判斷是否過期，TIMEOUT_BUCKETS為3，因此過期時間是三十秒
            if now_bucket - last_bucket > TIMEOUT_BUCKETS:
                print(f"[DELETE] {ip_to_str(key)}")

                delete_elem(time_fd, key)
                delete_elem(stats_fd, key)

        time.sleep(1)
```

python程式會掃過time map中的所有紀錄，並將紀錄中時間與現在時間差大於30秒的ip清除，所以還是O(N)。

刪除部分可以再優化，如果在bpf程式裡就用linklist把ip分好，這樣python端只要抓除來刪掉就好了。

