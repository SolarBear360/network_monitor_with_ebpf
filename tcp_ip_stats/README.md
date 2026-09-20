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

### init.sh
- 根據說明使用，用於掛載ebpf程式。


### tcpip_pakage_expire.py
- 刪除過期資料


### tcpip_stats.py
- 顯示統計數據

---

執行時，請按照以下順序:
1. 執行init.sh，掛載ebpf程式
2. 執行tcpip_pakage_expire.py

因為ebpf程式中使用了兩層map。掛載時，會先創立外層的map，再由tcpip_pakage_expire.py建立內部的map。過程中會有file directory相關操作，如果關閉了tcpip_pakage_expire.py，請務必也重新掛載ebpf程式(重新執行init.sh)，否則tcpip_pakage_expire.py會抓不到內部的file directory。

