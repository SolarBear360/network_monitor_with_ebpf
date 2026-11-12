# SYN Flood 流量測試流程

> 目前建議使用的 Ubuntu 隔離 Container + hping3 final holdout 流程，
> 請先閱讀 [`FINAL_HOLDOUT_USAGE.md`](FINAL_HOLDOUT_USAGE.md)。
> 下方前半部的 Mac、Nping 與 k6 內容是先前實驗流程。

這套工具的用途是在自己的局域網實驗環境中，用 Mac 對 Ubuntu 上的測試 Container 產生：

1. 低、高負載的正常 HTTP 流量。
2. 頻繁建立新 TCP 連線的正常 HTTP 流量。
3. 固定時間、固定速率的純 SYN 流量。
4. 正常 HTTP 與純 SYN 同時存在的混合流量。

拓撲如下：

```text
Mac（k6 / nping）
        |
        v
192.168.1.183:8080（Ubuntu）
        |
        v
ebpf-web-test:80（Docker Container）
        |
        v
Container veth 上的 TC/eBPF
```

## 一、必要安全限制

- 只能對你自己的測試主機執行。
- `run_experiment.sh` 只接受私有 IPv4，不接受域名或公網 IP。
- 腳本沒有使用 `nping --flood`，所有測試都有速率和時間上限。
- 第一次先使用 `--quick`，確認容器、Ubuntu 與 Mac 都穩定。
- 不要在學校、公司或共用網路中，對未授權的裝置執行。

## 二、Mac 安裝流量工具

```bash
brew install k6
brew install nmap
```

確認安裝：

```bash
k6 version
nping --version
```

`nping` 是 Nmap 所附的封包產生工具，不是 SAP 的 `niping`。

## 三、Ubuntu 準備受測容器

先確認容器和 port mapping：

```bash
sudo docker ps --format 'table {{.Names}}\t{{.Ports}}'
curl -I http://127.0.0.1:8080/
```

預期可看到類似：

```text
ebpf-web-test    0.0.0.0:8080->80/tcp
```

如果測試容器尚未存在，可用一個單純的 Nginx 測試容器：

```bash
sudo docker run --name ebpf-web-test -d -p 8080:80 nginx:alpine
```

## 四、Ubuntu 啟動 eBPF 與 CSV 收集

以下指令都從專案資料夾執行：

```bash
cd "/home/sean/下載/network_monitor_with_ebpf-main (13)/network_monitor_with_ebpf-main/tcp_ip_stats"
```

如果已有舊 CSV，先用改名的方式保留：

```bash
if [ -f tcp_stats.csv ]; then
  mv tcp_stats.csv "tcp_stats_backup_$(date '+%Y%m%d_%H%M%S').csv"
fi
```

終端機 1：掛載 eBPF，並保留該終端機。

```bash
./init.sh --container ebpf-web-test
```

終端機 2：啟動 bucket／過期資料處理。容器 IP 會由 `init.sh` 顯示；以下的 IP 只是範例。

```bash
sudo python3 tcpip_pakage_expire.py 172.17.0.2
```

終端機 3：啟動 CSV 收集。

```bash
sudo python3 tcpip_stats.py
```

確認 `tcp_stats.csv` 正在每秒新增一列：

```bash
tail -f tcp_stats.csv
```

## 五、檢查 Mac 與 Ubuntu 的時間

因為流量標籤由 Mac 記錄，統計 CSV 由 Ubuntu 記錄，兩台電腦的時間差最好不超過 1–2 秒。

在兩台電腦都執行：

```bash
date '+%s %Y-%m-%d %H:%M:%S %Z'
```

除了 Unix timestamp 要接近，時區也應一致。時間差太大時先開啟系統的自動日期與時間同步。

## 六、Mac 先做短測試

在 Mac 的專案資料夾執行：

```bash
chmod +x traffic_test/run_experiment.sh
./traffic_test/run_experiment.sh \
  --target 192.168.1.183 \
  --port 8080 \
  --quick
```

短測試只用來確認整條管線，不適合當正式訓練資料。

只想查看腳本會執行什麼，可使用：

```bash
./traffic_test/run_experiment.sh \
  --target 192.168.1.183 \
  --port 8080 \
  --quick \
  --dry-run
```

## 七、Mac 執行完整實驗

```bash
./traffic_test/run_experiment.sh \
  --target 192.168.1.183 \
  --port 8080 \
  --extended
```

完整實驗會依序產生：

| scenario | 內容 | label | 是否訓練 |
|---|---|---:|---:|
| `warmup` | 收集器預熱 | -1 | 否 |
| `idle` | 無主動測試流量 | 0 | 是 |
| `normal_http_low` | 5 個 k6 VUs | 0 | 是 |
| `normal_http_high` | 50 個 k6 VUs | 0 | 是 |
| `normal_http_new_connections` | 30 VUs，不重用連線 | 0 | 是 |
| `syn_50pps` | 50 個純 SYN／秒 | 1 | 是 |
| `syn_100pps` | 100 個純 SYN／秒 | 1 | 是 |
| `syn_200pps` | 200 個純 SYN／秒 | 1 | 是（`--extended`） |
| `mixed_http_syn` | 20 VUs + 100 個純 SYN／秒 | 1 | 是 |
| `cooldown_*` | 情境之間的緩衝 | -1 | 否 |

每個情境的輸出和標籤會放在：

```text
traffic_test/results/YYYYMMDD_HHMMSS/
```

其中最重要的檔案是 `scenario_labels.csv`。

### 多輪改變正常流量與 SYN 速率

`run_multi_round_experiment.sh` 預設執行下列四輪：

| 輪次 | 正常 HTTP 強度 | 純 SYN 速率 |
|---:|---:|---:|
| 1 | 10 VUs | 30 packets/s |
| 2 | 30 VUs | 70 packets/s |
| 3 | 70 VUs | 150 packets/s |
| 4 | 70 VUs | 250 packets/s |

先執行短版，確認整條管線：

```bash
chmod +x traffic_test/run_multi_round_experiment.sh
./traffic_test/run_multi_round_experiment.sh \
  --target 192.168.1.183 \
  --port 8080 \
  --quick
```

正式收集時移除 `--quick`：

```bash
./traffic_test/run_multi_round_experiment.sh \
  --target 192.168.1.183 \
  --port 8080
```

每輪都會依序收集 idle、指定 VUs 的正常 HTTP、指定 VUs 且不重用連線的正常 HTTP、指定速率的純 SYN，以及兩者同時出現的混合流量。自訂組合的格式是 `VUS:SYN_RATE`：

```bash
./traffic_test/run_multi_round_experiment.sh \
  --target 192.168.1.183 \
  --profiles 10:30,30:70,70:150,70:250
```

輸出會放在 `traffic_test/results/batch_日期時間/`。每輪都有獨立的 `run_id` 和 `scenario_labels.csv`，因此模型可以按照整輪分組，避免把同一輪相鄰秒數同時分到訓練集與測試集。

### 低速 SYN 邊界實驗

當模型在「10 VUs 正常 HTTP + 30 pps 純 SYN」附近容易漏判時，
可在 Mac 上執行專用腳本：

```bash
chmod +x traffic_test/run_low_rate_boundary_experiment.sh

./traffic_test/run_low_rate_boundary_experiment.sh \
  --target 192.168.1.183 \
  --port 8080
```

建議先加上 `--quick --dry-run`檢查流程。實驗會比較 10 VUs 搭配
5、10、15、20、25、30、35 與 40 pps 純 SYN 的情境，並保留正常與
70 pps 攻擊對照組。這些 5–40 pps 混合情境預設為診斷資料
(`label=-1`, `include_in_training=0`)，跑完後先比較模型機率、HTTP 錯誤率
與延遲，再決定如何標記，不應直接加入訓練。

## 八、停止 Ubuntu 收集器

等 Mac 顯示「全部情境完成」後：

1. 先停止終端機 3 的 `tcpip_stats.py`。
2. 再停止終端機 2 的 `tcpip_pakage_expire.py`。
3. 最後停止終端機 1 的 `init.sh`，讓它正常卸載 TC filter 和 map。

## 九、將 Mac 標籤複製到 Ubuntu

單輪實驗時，在 Mac 執行，將實際結果資料夾名稱填入指令：

```bash
scp \
  traffic_test/results/YYYYMMDD_HHMMSS/scenario_labels.csv \
sean@192.168.1.183:/tmp/scenario_labels.csv
```

多輪實驗則複製整個批次資料夾：

```bash
scp -r \
  traffic_test/results/batch_YYYYMMDD_HHMMSS \
  sean@192.168.1.183:/tmp/
```

## 十、在 Ubuntu 合併統計與標籤

```bash
cd "/home/sean/下載/network_monitor_with_ebpf-main (13)/network_monitor_with_ebpf-main/tcp_ip_stats"

python3 traffic_test/merge_labels.py \
  --stats tcp_stats.csv \
  --labels /tmp/scenario_labels.csv \
  --output tcp_stats_labeled.csv \
  --boundary-seconds 3
```

多輪資料可以一次傳入所有標籤檔：

```bash
python3 traffic_test/merge_labels.py \
  --stats tcp_stats.csv \
  --labels /tmp/batch_YYYYMMDD_HHMMSS/run_*/scenario_labels.csv \
  --output tcp_stats_labeled_multi.csv \
  --boundary-seconds 6
```

如果兩台電腦的時鐘最多相差約 3 秒，先使用 `--boundary-seconds 6` 排除情境交界；時間同步改善後可縮回 3 秒。

`--boundary-seconds 3` 會排除每個情境開始與結束的各 3 秒，避免指令啟動延遲、殘留封包與時間誤差造成錯誤標籤。

合併後的 `tcp_stats_labeled.csv` 會多出：

- `run_id`
- `scenario`
- `label`：0 為正常，1 為人為純 SYN 情境。

## 十一、預期結果與異常判斷

- `idle`：`tcp_packets` 和 `syn_only_packets` 應很低，但不一定為 0。
- 正常 HTTP：`tcp_packets` 會增加，但 SYN 只是所有 TCP 封包中的一部分。
- 關閉連線重用：正常流量的 SYN 也會增加，這是很重要的「困難正常範例」。
- 純 SYN 情境：`syn_only_packets` 應明顯增加，數量級應大致跟設定速率同階。
- 如果 SYN 數量完全沒改變，先檢查 eBPF 是否掛在正確容器的 veth，以及 Mac 是否真的連到公開的 8080 port。

## 十二、目前資料的限制

1. `nping --tcp --flags SYN` 很適合產生 SYN 異常訊號，但這個有上限的實驗不等於真的大規模 DDoS，也不代表已將 server backlog 壓滿。
2. 現行 eBPF 程式會排除容器發出的封包，因此 `syn_ack_packets` 不應當這一版模型的主要特徵。
3. 目前的 `established_connections` 是從 flow 狀態推測，不是 sockops 提供的精確完成握手數，第一版訓練先不使用。
4. 第一版可先使用 `tcp_packets`、`syn_only_packets`、`tcp_bytes`，並額外計算 `syn_only_packets / max(tcp_packets, 1)`。
5. 不要將 `timestamp`、`run_id` 或情境執行順序當成模型特徵。
6. 短測試只是管線驗證。正式收集應至少重複 5 輪，並在不同時間、不同正常負載下收集。

## 十三、進階完整實驗

前面的多輪實驗適合建立第一版模型，但對「正常低量 SYN」與攻擊邊界的
測試不夠。`run_comprehensive_experiment.sh` 額外加入：

- 每秒 `1,2,5,10,30` 個真正完成握手的正常新 HTTP 連線。
- `10,70` VUs 的正常 keep-alive HTTP 負載。
- 每秒 `1,2` 個低量純 SYN 背景雜訊，標記為非 flood。
- 每秒 `5,10,20` 個純 SYN 的診斷區，只供觀察而不加入訓練。
- 每秒 `30,70,150,250` 個純 SYN 的攻擊情境。
- 10 秒短攻擊，以及正常 HTTP 與 SYN 同時出現的混合情境。

`normal_tcp_connections.py` 會實際完成 TCP 握手、發送 HTTP request 並檢查
response，不是單純發 SYN。成功率低於 90% 時會讓該情境失敗，防止將
「服務器已經不正常」的資料誤標為正常。

先在 Mac 做 dry run：

```bash
chmod +x traffic_test/run_comprehensive_experiment.sh

./traffic_test/run_comprehensive_experiment.sh \
  --target 192.168.1.183 \
  --port 8080 \
  --quick \
  --dry-run
```

確認 Ubuntu 上的 eBPF 與 CSV 收集器都在執行後，先做實際短測：

```bash
./traffic_test/run_comprehensive_experiment.sh \
  --target 192.168.1.183 \
  --port 8080 \
  --quick
```

正式收集：

```bash
./traffic_test/run_comprehensive_experiment.sh \
  --target 192.168.1.183 \
  --port 8080
```

進階腳本在 Mac 上會自動啟動 `caffeinate`，防止長時間實驗途中進入睡眠。
開始時會要求一次 sudo 密碼，之後每 60 秒以 `sudo -n -v` 更新認證時效，
因此執行 Nping 時不會因 sudo 快取過期而停下等待再次輸入密碼。這個機制不會
儲存密碼，且會在實驗腳本結束時停止。
每個情境也會檢查實際執行時間；若遠超過預期，腳本會停止並將該段標記為
不納入訓練，接著繼續後續情境，避免電腦睡眠後產生數百秒的
錯誤標籤，也不會因一段異常而損失後半部實驗。若 Mac 關上屏幕上蓋，
`caffeinate` 仍無法保證不睡眠，所以實驗期間不要關蓋。

要縮小或改變實驗範圍，可以自訂數列：

```bash
./traffic_test/run_comprehensive_experiment.sh \
  --target 192.168.1.183 \
  --normal-rates 1,2,5,10 \
  --background-syn-rates 1,2 \
  --diagnostic-syn-rates 5,10,20 \
  --attack-syn-rates 30,70,150 \
  --mixed-profiles 10:30,30:70
```

完成後一樣將 `scenario_labels.csv` 複製到 Ubuntu，再使用
`merge_labels.py`。其中 `label=-1` 或 `include_in_training=0` 的低速診斷情境，
預設不會被合併到訓練 CSV。

如果要另存一份包含診斷區的 CSV，用來觀察模型機率：

```bash
python3 traffic_test/merge_labels.py \
  --stats tcp_stats.csv \
  --labels /tmp/comprehensive_YYYYMMDD_HHMMSS/scenario_labels.csv \
  --output tcp_stats_with_diagnostic.csv \
  --boundary-seconds 3 \
  --include-diagnostic
```

`tcp_stats_with_diagnostic.csv` 中的 `label=-1` 代表「尚未定義成正常或 flood」，
不可直接交給現有的二元分類訓練程式。正式訓練仍使用沒有
`--include-diagnostic` 的預設合併指令。

如果某一段實驗已確認失敗，可在不修改原始 `scenario_labels.csv` 的情況下
明確排除：

```bash
python3 traffic_test/merge_labels.py \
  --stats tcp_stats.csv \
  --labels traffic_test/comprehensive_YYYYMMDD_HHMMSS/scenario_labels.csv \
  --output tcp_stats_labeled_comprehensive.csv \
  --boundary-seconds 3 \
  --exclude-scenario benign_background_syn_1pps
```

## 十四、獨立 final holdout 測試（Ubuntu + hping3 Container）

`run_final_holdout_experiment.sh` 是模型凍結後的最後評估，不再使用 Mac。
正常 HTTP 由 Ubuntu 產生，SYN Flood 由與受測 Container 同一個
Docker 內部網路中的 hping3 Container 產生。

它包含：

- idle、多種正常新連線速率、多種 keep-alive 負載。
- 1、2 pps 低量背景 SYN 的誤報測試。
- 5、10、20 pps 不計分的邊界診斷。
- 30、70、150、250 pps 的單來源長時間 SYN Flood。
- 30、70、150、250 pps 的 `hping3 --rand-source` 攻擊，每封包使用隨機來源 IP。
- 正常 HTTP 與單來源／隨機來源 SYN Flood 同時發生。
- 短攻擊、情境之間的 cooldown 與告警恢復。

因為 `--rand-source` 會產生任意來源 IP，腳本只允許在專用的
Docker `--internal` 網路執行。受測 Container 必須只有這一個網路，
也不能使用 `-p` 對 Host 發布 port。腳本會在發封包前檢查這兩項，
任一項不符合就停止。

先建立一個新的隔離受測 Container；不要直接把原本使用中的
Container 斷網，也不要額外接第二個網路，因為 eBPF 要監測它唯一的 `eth0`：

```bash
chmod +x traffic_test/create_isolated_synlab.sh
./traffic_test/create_isolated_synlab.sh
```

再啟動 eBPF 與 CSV 收集器：

```bash
./init.sh --container ebpf-final-target
sudo python3 tcpip_pakage_expire.py 172.30.0.2
sudo python3 tcpip_stats.py
```

`172.30.0.2` 只是常見範例，請以建立腳本最後顯示的 Container IP 為準。

在第四個終端先檢查測試計畫：

```bash
./traffic_test/run_final_holdout_experiment.sh --dry-run
```

執行完整測試（預設約一小時）：

```bash
./traffic_test/run_final_holdout_experiment.sh \
  --target-container ebpf-final-target \
  --target-port 80
```

腳本會自動建置 hping3 image、建立攻擊 Container、合併標籤、使用已凍結的
runtime model 評估，然後輸出 `evaluation/SUMMARY.md`。

不發送真實流量、只測試 hping3 結束狀態判斷：

```bash
./traffic_test/test_hping3_multi_source.sh
```

`scenario_labels.csv` 中的 `include_in_training` 全部為 0；只有可計分情境的
`include_in_evaluation` 為 1。`final_holdout_labeled.csv` 不可加回模型訓練。

注意：目前模型並沒有使用「不同來源 IP 數」作為特徵，因此隨機來源測試
主要是驗證收集器、BPF flow map 與現有特徵在大量不同來源下是否穩定，
不是期待單純因為 IP 變多就讓模型機率提高。
