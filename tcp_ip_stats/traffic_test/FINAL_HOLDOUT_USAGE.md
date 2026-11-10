# Traffic Test 使用手冊（最終隔離版）

這份文件以 2026-11-09 最後定案的測試流程為主：

- 所有測試都在 Ubuntu 主機上執行，不再依賴 Mac。
- 受測 Container 與 hping3 Container 只連接同一個 Docker `--internal` 網路。
- 受測 Container 不對 Host 發布 port。
- 包含單一來源與 `hping3 --rand-source` 的 SYN Flood 情境。
- 結果是模型的 final holdout，只用來評估，不能加回訓練資料。

> 只能在自己的隔離實驗環境執行。不要對未經授權的主機、容器或網路發送測試流量。

## 1. 主要腳本

| 檔案 | 用途 | 是否手動執行 |
|---|---|---:|
| `create_isolated_synlab.sh` | 建立隔離的 Docker 網路與 Nginx 受測 Container | 是，第一次執行 |
| `run_final_holdout_experiment.sh` | 執行完整正常流量、SYN Flood、混合流量與模型評估 | 是 |
| `hping3.Dockerfile` | 建立內含 hping3 的實驗 image | 否，由主腳本自動處理 |
| `hping3_multi_source.sh` | 在攻擊 Container 內發送單來源或隨機來源 SYN | 否，由主腳本自動呼叫 |
| `normal_tcp_connections.py` | 以固定速率建立真正完成握手的 HTTP 連線 | 通常不用手動執行 |
| `normal_http_keepalive.py` | 產生可控 VUs 的正常 HTTP keep-alive 流量 | 通常不用手動執行 |
| `merge_labels.py` | 依情境開始與結束時間，把標籤合併到 `tcp_stats.csv` | 主腳本會自動執行 |

`run_experiment.sh`、`run_multi_round_experiment.sh`、
`run_comprehensive_experiment.sh` 與 `run_low_rate_boundary_experiment.sh`
是之前使用 Mac、Nping 與 k6 的舊流程，本分支未收錄。現在的 final holdout 實驗不需要執行它們。

## 2. 環境架構

```text
Ubuntu 主機
├── 正常 HTTP 產生器（Python）
├── eBPF / TC 統計程式
├── tcpip_stats.py 與 SYN Flood 模型
│
└── Docker internal network: synlab-internal
    ├── ebpf-final-target（受測 Nginx）
    └── synlab-hping-...（攻擊流量產生器）
```

受測 Container 只有一個 `eth0`，eBPF 會掛在它對應的 Host veth。
雖然沒有發布 Host port，Ubuntu Host 仍可以直接透過 Container 的內部 IP 產生正常 HTTP 流量。

## 3. 第一次建立隔離環境

所有指令均在 repository 內的 `tcp_ip_stats` 執行。從 clone 的 repository 根目錄開始：

```bash
cd tcp_ip_stats
```

賦予腳本執行權限：

```bash
chmod +x traffic_test/create_isolated_synlab.sh
chmod +x traffic_test/run_final_holdout_experiment.sh
chmod +x traffic_test/hping3_multi_source.sh
```

建立預設實驗環境：

```bash
./traffic_test/create_isolated_synlab.sh
```

預設會建立：

- 內部網路：`synlab-internal`
- 子網：`172.30.0.0/24`
- 受測 Container：`ebpf-final-target`
- image：`nginx:alpine`
- Host port：無

腳本最後會顯示受測 Container IP，例如 `172.30.0.2`。
後續啟動 `tcpip_pakage_expire.py` 時要使用實際顯示的 IP。

如果需要自訂名稱：

```bash
./traffic_test/create_isolated_synlab.sh \
  --network my-synlab \
  --subnet 172.31.0.0/24 \
  --container my-ebpf-target \
  --image nginx:alpine
```

這支腳本不會自動刪除或取代已存在的 Container。如果同名 Container 已存在，它會停止並要求使用另一個名稱。

## 4. 啟動 eBPF 與收集器

完整實驗需要四個終端機視窗，各終端都先進入 repository 內的 `tcp_ip_stats` 目錄。前三個終端在實驗期間都不能關閉。

### 終端 1：掛載 eBPF

```bash
./init.sh --container ebpf-final-target
```

`init.sh` 會顯示 Container IP 與對應的 Host veth。按 `Ctrl+C` 會卸載 TC filter 與 pinned map，所以實驗完成前不要停止它。

### 終端 2：bucket 與過期 flow 清理

```bash
sudo python3 tcpip_pakage_expire.py 172.30.0.2
```

將 `172.30.0.2` 換成終端 1 實際顯示的 Container IP。

### 終端 3：每秒統計與模型推論

```bash
sudo python3 tcpip_stats.py
```

它會持續寫入：

- `tcp_stats.csv`：每秒 eBPF 統計。
- `syn_flood_predictions.csv`：每秒模型機率、candidate 與 ATTACK/NORMAL 狀態。

可以用另一個終端檢查 CSV 是否持續增加：

```bash
tail -f tcp_stats.csv
```

同一時間只能執行一個 `tcpip_stats.py`，否則會產生重複列與不一致的差分結果。

## 5. 先做 dry run

在終端 4 執行：

```bash
./traffic_test/run_final_holdout_experiment.sh --dry-run
```

Dry run 只會：

- 產生 `test_plan.csv`。
- 顯示預估時間。
- 檢查腳本參數。

Dry run 不會連線 Docker、不會發封包，也不會執行模型評估。

## 6. 執行正式 final holdout

```bash
./traffic_test/run_final_holdout_experiment.sh \
  --target-container ebpf-final-target \
  --target-port 80
```

預設約需要 57 分 41 秒。執行前腳本會自動檢查：

1. 受測 Container 是否正在執行。
2. Container 是否只連接一個 Docker 網路。
3. 該網路是否為 `--internal`。
4. Container 是否沒有對 Host 發布 port。
5. Ubuntu 是否可以透過內部 IP 存取 Nginx。
6. `tcp_stats.csv` 是否每秒持續增加。

檢查通過後，腳本會自動：

1. 建立最新的 hping3 image。
2. 在相同 internal network 建立專用攻擊 Container。
3. 依測試計畫執行正常、攻擊與混合情境。
4. 產生時間標籤。
5. 合併 `tcp_stats.csv` 與情境標籤。
6. 使用凍結的 runtime model 執行 final holdout 評估。
7. 預設刪除臨時 hping3 Container。

## 7. 測試情境

| 類型 | 內容 | 標籤 | 納入評估 |
|---|---|---:|---:|
| `warmup` | 收集器預熱 15 秒 | -1 | 否 |
| `idle` | 沒有主動測試流量 | 0 | 是 |
| `normal_completed_*cps` | 1、10、30、70 個/秒正常新 HTTP 連線 | 0 | 是 |
| `normal_keepalive_*vus` | 10、30、70 VUs 正常 keep-alive HTTP | 0 | 是 |
| `benign_background_syn_*pps` | 1、2 pps 低量背景 SYN | 0 | 是 |
| `diagnostic_syn_*pps` | 5、10、20 pps 邊界觀察 | -1 | 否 |
| `attack_short_single_70pps` | 8 秒單來源短攻擊 | 1 | 是 |
| `attack_short_rand_150pps` | 8 秒、每封包隨機來源 IP | 1 | 是 |
| `attack_single_*pps` | 30、70、150、250 pps 單來源攻擊 | 1 | 是 |
| `attack_rand_*pps` | 30、70、150、250 pps 隨機來源攻擊 | 1 | 是 |
| `mixed_single_*` | 正常 HTTP + 單來源攻擊 | 1 | 是 |
| `mixed_rand_*` | 正常 HTTP + 隨機來源攻擊 | 1 | 是 |
| `cooldown_*` | 等待告警狀態恢復 | -1 | 否 |

這裡的 `label=1` 代表「此秒處在人工建立的 SYN Flood 測試情境」，
`label=0` 代表正常或明確被定義為非 flood 的情境，`label=-1` 不計分。

## 8. 常用參數

```text
--target-container NAME  受測 Container，預設 ebpf-final-target
--target-port PORT       Container 內的 HTTP port，預設 80
--phase-seconds SEC      正常與診斷情境秒數，範圍 30–300，預設 90
--attack-seconds SEC     主要攻擊秒數，範圍 30–300，預設 120
--cooldown SEC           情境間隔，範圍 10–120，預設 20
--stats-csv FILE         正在增加的統計 CSV，預設專案根目錄/tcp_stats.csv
--output-dir DIR         指定結果目錄
--dry-run                只產生計畫，不發封包
--keep-attacker          實驗完成後保留 hping3 Container
-y, --yes                略過執行前確認
```

例如以最低允許時間執行一次較短的管線驗證：

```bash
./traffic_test/run_final_holdout_experiment.sh \
  --target-container ebpf-final-target \
  --phase-seconds 30 \
  --attack-seconds 30 \
  --cooldown 10
```

這仍會執行所有情境，只是縮短單段時間；不應把它當成完整正式評估。

## 9. 輸出檔案

預設輸出位置：

```text
traffic_test/results/final_holdout_YYYYMMDD_HHMMSS/
```

| 檔案 | 內容 |
|---|---|
| `test_plan.csv` | 本輪完整測試計畫 |
| `scenario_labels.csv` | 每個情境的實際開始、結束時間與標籤 |
| `metadata.txt` | Container、IP、Docker 網路、模型與時間參數 |
| `*.log` | 各情境的命令輸出 |
| `final_holdout_labeled.csv` | 已對齊標籤的每秒資料 |
| `evaluation/SUMMARY.md` | 最終摘要與準確率結果 |
| `evaluation/predictions.csv` | 評估階段逐秒預測結果 |
| `evaluation/scenario_summary.csv` | 各情境的評估摘要 |
| `evaluation/evaluation.json` | 完整指標與限制 |

`scenario_labels.csv` 內的 `include_in_training` 固定為 `0`。
`final_holdout_labeled.csv` 不能加回訓練集，否則就不再是獨立測試。

## 10. 單獨使用正常流量腳本

通常由 final holdout 主腳本自動呼叫。需要除錯時，可手動執行。

### 每秒建立指定數量的正常新連線

```bash
python3 traffic_test/normal_tcp_connections.py \
  --host 172.30.0.2 \
  --port 80 \
  --rate 10 \
  --duration 30
```

`--rate` 範圍為 1–200，`--duration` 範圍為 5–300 秒。
預設成功率低於 90% 時會以失敗結束。

### 產生正常 HTTP keep-alive VUs

```bash
python3 traffic_test/normal_http_keepalive.py \
  --host 172.30.0.2 \
  --port 80 \
  --vus 10 \
  --duration 30
```

`--vus` 範圍為 1–200，`--duration` 範圍為 5–300 秒。

## 11. 手動合併標籤

主腳本完成時會自動合併。如果需要重新產生 final holdout CSV：

```bash
python3 traffic_test/merge_labels.py \
  --stats tcp_stats.csv \
  --labels traffic_test/results/final_holdout_YYYYMMDD_HHMMSS/scenario_labels.csv \
  --output traffic_test/results/final_holdout_YYYYMMDD_HHMMSS/final_holdout_labeled.csv \
  --boundary-seconds 3 \
  --include-evaluation-only
```

`--boundary-seconds 3` 會排除每個情境開始與結束附近的 3 秒，避免指令啟動延遲、殘留封包與時間對齊誤差。

## 12. 執行中的正常現象

- `run_final_holdout_experiment.sh` 的畫面會顯示情境開始與最後結果，子程式輸出會寫入對應的 `*.log`。
- 1 pps 單來源情境中，`syn_only_packets` 應約為每秒 1。
- hping3 所在 Container 的 TCP/IP stack 可能對 SYN-ACK 回傳 RST，因此 `tcp_packets` 可能約為 SYN 數的兩倍。
- 單一來源重複使用相同 5-tuple 時，`syn_source_ips` 與 `syn_flows` 不會每秒都增加。
- cooldown 中的模型狀態可能因「最近 3 秒」持續性規則而短暫保持 ATTACK，這些秒數不會納入評估。

## 13. 常見問題

### `Docker 網路不是 --internal`

代表使用了一般 `bridge` 網路。請改用：

```bash
./traffic_test/create_isolated_synlab.sh
```

不要只把新網路額外接到舊 Container；受測 Container 必須只有一個內部網路，才能確定 eBPF 監測的是 `eth0`。

### `Container 仍有對 Host 發布的 port`

受測 Container 不能用 `-p` 或 `--publish` 建立。請使用隔離環境腳本建立新 Container。

### `tcp_stats.csv 沒有持續增加`

確認：

1. `init.sh` 的終端仍然開著。
2. `tcpip_pakage_expire.py` 使用正確的 Container IP。
3. `tcpip_stats.py` 正在執行。
4. 沒有同時執行兩個 `tcpip_stats.py`。

### `benign_background_syn_1pps` 只有第一秒有資料

舊版把 1 pps 轉為 `hping3 --interval u1000000`，可能在第一包後卡住。
現行版本已改用 `--interval 1` 並加入逾時保護。
重新執行 final holdout 腳本時會自動重建 hping3 image，不要繼續使用舊攻擊 Container。

### 測試中斷

中斷後已完成的 log 與標籤會保留，但這輪不應當成完整 final holdout。
排除問題後重新執行，腳本會建立新的時間戳結果目錄。

### 隨機來源攻擊讓 flow map 壓力變大

`--rand-source` 會產生大量不同的 5-tuple，因此會比單一來源更容易接近 BPF map 容量。
這正是這個情境要觀察的收集器穩定性之一。如果出現 map 更新失敗，該時段資料不應當成完整樣本。
目前程式尚未回報 map 寫入失敗計數，模型的品質欄位不能證明 map 沒有遺漏；需另外核對產生器及收集數據。

偽造來源的 SYN-ACK 會送往偽造的 IP，因此攻擊 Container 顯示沒有收到回覆是預期行為。腳本會核對 hping3 摘要中的實際送出數；只有預定封包全數送完時，才會把「沒有收到回覆」的結束狀態視為成功。少送、逾時或缺少摘要仍會中止測試。

## 14. 正確停止順序

實驗完成後：

1. 確認 `run_final_holdout_experiment.sh` 已輸出評估報告路徑。
2. 停止終端 3 的 `tcpip_stats.py`。
3. 停止終端 2 的 `tcpip_pakage_expire.py`。
4. 最後按 `Ctrl+C` 停止終端 1 的 `init.sh`，讓它卸載 eBPF。

隔離的受測 Container 與 internal network 會保留，下次實驗可繼續使用。
臨時 hping3 Container 預設會由主腳本自動刪除。
