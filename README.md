# network_monitor_with_ebpf

此專案透過ebpf(tc)來檢測封包，並記錄到bpf map中。再由python讀取bpf map以便做流量分析。

## 如何使用
此專案有三個檔案 :
- network_flow_detect_init.sh
- network_flow_analysis.py
- tc_network_flow.c

`sudo ./network_flow_detect_init.sh -h` 可以查看參數，主要參數有兩個 :

- -t、--tc-prog : 要掛載的bpf程式，network_flow_detect_init.sh 會自動編譯，因此確保傳入的是c程式
- -c、--container : 要檢測的容器名稱，如果用指令開啟一個容器 : 
`sudo docker start -i ebpf-test-container`
則名稱就是 ebpf-test-container

**注意** : 要先創建、執行容器，再執行network_flow_detect_init.sh

範例 : `sudo ./network_flow_detect_init.sh -t tc_network_flow.c -c ebpf-test-container`

掛載好後，就可以執行network_flow_analysis.py做分析
`sudo python3 network_flow_analysis.py`

這時，當有流量出入容器時(可以進入容器的互動模式，並在容器中ping一個外部ip。
例如`ping 8.8.8.8`)，而python程式就能夠從map讀取封包數量以及流量(bytes)。

## 可能的發展方向
bpf所攔截的封包包含其他網路分層的header，因此可以做到讓bpf封鎖特定ip，但這樣有以下問題 :

- bpf map的大小在載入時就要決定好，因此沒辦法根據流量改變map大小來新增或刪除封鎖的ip，或者說如果要做到，那就可能會需要user space的程式幫忙，只是就失去了ebpf的性能優勢。如果說封鎖特定數量的ip(例如10000個)，這樣的可行性比較高。但是要分析讓ebpf每個封包都掃過10000個對性能的影響。
