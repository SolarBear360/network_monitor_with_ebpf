# tcp 連線封包紀錄

- 此程式要獲取的資料 : 

1. tcp封包數量(一秒內)
2. syn=1,ack=0封包數量(一秒內)
3. syn=1,ack=1封包數量(一秒內)
4. syn=1,ack=0不同ip來源(一秒內)
5. syn=1,ack=0 不同tcp 5-tuple數量(一秒內)
6. 真正完成握手的連線數(此秒接收到已完成的連線封包數)
7. 當下這一秒的開始時間(當前讀取bucket的時間)
8. 資料品質狀態(ebpf滿了無法紀錄時，更新失敗)

ebpf map如下 :

**key** : 
- source_ip
- destination_ip
- srouce_port
- destination_port
- protocol(基本上是tcp)

**value** : 
- packets(封包數)
- bytes
- connection_state(tcp三項交握的狀態如何)
- syn
- ack
- first_seen(此ip最初一次傳送封包的時間)
- last_seen(此ip最後一次傳送封包的時間)

## 補充說明
- 收到syn=1,ack=0或syn=1,ack=1兩種封包，則數值為1的欄位加1
- 當收到syn=0,ack=1視為完成三項交握,ack欄位不加1
- 目前python是1秒讀1次，所以第七點**當下這一秒開始時間**可以都以隔一秒計算。

## 更新

現在tcp_ip_stats有4個檔案
- init.sh
- tc_tcpip_stats.c
- tcpip_pakage_expire.py
- tcpip_stats.py

### tc_tcpip_stats.c
- ebpf 程式
- 紀錄收集到的封包資訊

### init.sh
- 根據說明使用，用於掛載ebpf程式。


### tcpip_pakage_expire.py
- 刪除過期資料，超過30秒未傳送封包的ip的所有紀錄會被刪除
- 只記錄伺服器接收到的封包
- 執行時需要一個參數:被偵測的容器的ip,可以進入容器的互動模式查看其中的eth0 ip


### tcpip_stats.py
- 顯示統計數據
- 輸出csv檔案
- `active_source_ips` 會統計本輪確實有新增封包的不同入站來源 IP；
  同一 IP 若下一輪仍有傳送，下一輪會再次被計入
- `syn_flows` 會統計本輪確實收到純 SYN 的不同 TCP 5-tuple；
  同一 5-tuple 在同一輪內重傳只算一個，下一輪又收到純 SYN 時會再計入
- `syn_source_ips` 會統計本輪確實收到純 SYN 的不同來源 IP；
  同一 IP 在同一輪使用多個 5-tuple 或重傳多個 SYN，仍只算一個
- 每秒使用 `syn-window-v1` 進行一次 SYN Flood 推論
- 模型結果另存在 `syn_flood_predictions.csv`，不會破壞原本的
  `tcp_stats.csv` 格式

新版 CSV 新增了 `active_source_ips`。如果目錄中已有舊格式的
`tcp_stats.csv` 或 `syn_flood_predictions.csv`，程式會停止並提示先備份／改名，
避免把不同欄位格式的資料寫進同一個檔案。

---

執行時，請按照以下順序:
1. 執行init.sh，掛載ebpf程式
2. 執行tcpip_pakage_expire.py
3. 執行 `sudo python3 tcpip_stats.py`

因為ebpf程式中使用了兩層map。掛載時，會先創立外層的map，再由tcpip_pakage_expire.py建立內部的map。過程中會有file directory相關操作，如果關閉了tcpip_pakage_expire.py，請務必也重新掛載ebpf程式(重新執行init.sh)，否則tcpip_pakage_expire.py會抓不到內部的file directory。

## SYN Flood 即時判斷

預設使用以下暫定告警標準：

1. 模型攻擊機率至少 `0.5`。
2. 當秒至少有 `5` 個入站純 SYN。
3. 最近 `3` 秒中至少 `2` 秒同時符合上述條件。
4. 進入攻擊狀態後，連續 `3` 秒正常才解除。

終端會每秒顯示：

- `NORMAL`：目前正常。
- `SUSPECT`：這一秒異常，但還未滿足持續性規則。
- `ATTACK`：已滿足攻擊規則。
- `INSUFFICIENT_DATA`：窗口時間不完整，此秒不改變告警狀態。

門檻可由參數調整，例如：

```bash
sudo python3 tcpip_stats.py \
  --probability-threshold 0.5 \
  --minimum-syn 5 \
  --alert-window 3 \
  --alert-hits 2 \
  --clear-seconds 3
```

只要收集資料、不執行模型時：

```bash
sudo python3 tcpip_stats.py --no-model
```

這些門檻仍是實驗原型，`ATTACK` 不應直接觸發永久封鎖。
