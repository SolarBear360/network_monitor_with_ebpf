# 每秒 TCP 統計與 SYN Flood 實驗

這個專題用 eBPF 觀察受測 Docker Container 的 TCP 封包，由 Python 每秒讀取 flow map 的累積值並計算差值，再交給 `syn-window-v1` 模型輸出攻擊機率與告警狀態。

目前的測試流程為 Ubuntu 原生 Docker、專用 internal network、正常 HTTP 產生器及 hping3 Container。完整操作請看 [final holdout 使用手冊](traffic_test/FINAL_HOLDOUT_USAGE.md)。

## 環境

- Ubuntu Linux x86_64；收集器使用 x86_64 的 BPF syscall 編號。
- Python 3.12 以上；過期清理程式使用 Python 3.12 支援的 f-string 語法。
- 原生 Docker Engine（使用 `default` context）、可用的 sudo 權限。
- `clang`、`libbpf` 標頭、`bpftool`、`ip`、`tc`、`curl`、`awk`。
- image 下載及建置需要網路；正式流量測試在 Docker internal network 內進行。

若 Ubuntu 尚缺少編譯與網路工具，可安裝：

```bash
sudo apt update
sudo apt install clang libbpf-dev linux-tools-common linux-tools-generic iproute2 curl python3 python3-venv
bpftool version
docker --context default info
```

若目前 kernel 對應的 `bpftool` 尚未安裝，請安裝與 kernel 相容的 Ubuntu Linux tools 套件。`vmlinux.h` 已一併提供；`init.sh` 會在本機重新編譯 `.o`，不需下載預編譯物件。

即時模型、final holdout 產生器及 final holdout 評估程式只需 Python 標準函式庫。重新訓練、joblib 模型與進階評估需要額外套件，見 [ml_test 說明](ml_test/README.md)。

## 快速開始

在 repository 根目錄進入子專案：

```bash
cd tcp_ip_stats
./traffic_test/create_isolated_synlab.sh
```

記下腳本顯示的 Container IP。在四個終端分別進入相同的 `tcp_ip_stats` 目錄：

```bash
# 終端 1，持續保持執行
./init.sh --container ebpf-final-target
```

```bash
# 終端 2：IP 請以建立腳本的實際輸出為準
sudo python3 tcpip_pakage_expire.py 172.30.0.2
```

```bash
# 終端 3
sudo python3 tcpip_stats.py
```

```bash
# 終端 4，預覽計畫；此命令不產生流量
./traffic_test/run_final_holdout_experiment.sh --dry-run

# 正式實驗，預設約 58 分鐘
./traffic_test/run_final_holdout_experiment.sh --target-container ebpf-final-target
```

僅在自己的專用實驗環境執行。正式腳本要求受測 Container 只連接一個 `--internal` 網路且沒有發布 Host port。正常流量與攻擊產生器都在同一台實體主機上，因此效能結果包含資源競爭，不能當成獨立攻擊機的效能基準。

## 模型與資料

凍結模型位於 [`model_handoff/syn-window-v1/`](model_handoff/syn-window-v1/)。即時程式讀取 `runtime_model.json`，輸入為 `tcp_packets`、`tcp_bytes`、`syn_only_packets`，並計算 SYN 比例。

預設告警條件：機率至少 0.5、當秒至少 5 個純 SYN、最近 3 秒至少 2 秒符合；連續 3 秒正常後解除。這些是實驗中的告警規則，程式不會自動封鎖流量。

大型 PCAP、逐秒實驗 CSV、log、虛擬環境與編譯結果未收錄。唯一收錄的 CSV 是模型套件內兩筆人工範例 `example_input.csv`。模型套件中的小型評估摘要為既有實驗紀錄，不是本次 final holdout 的結果。

每次執行會在 `traffic_test/results/` 產生獨立資料夾。final holdout 的 `include_in_training` 固定為 0；若依測試結果再調整模型，下一次應重新收集獨立測試資料。

## 原有 flow map 與過期清理

沿用原專案的 flow map 格式：key 是來源／目的 IP、來源／目的 port 與 protocol；value 記錄封包數、bytes、SYN／ACK 計數、推測的 TCP 連線狀態，以及首次／最後觀察時間。Python 讀取各 CPU 的值並彙總後，再與上次快照計算差值。

`tcpip_pakage_expire.py` 負責初始化內層 bucket map、設定受測 Container IP，並清理超過約 30 秒未更新的 flow。啟動順序仍為 `init.sh`、`tcpip_pakage_expire.py`、`tcpip_stats.py`。

清理程式持有內層 map 的 file descriptor；若它停止，請先停止收集器與 `init.sh`，再依上述順序重新啟動整組程式，避免使用殘留的 map／descriptor 狀態。

## 目前限制

- 收集方式為每個 flow 的累積值差分，並非已完成的固定一秒 bucket array。
- eBPF 目前會排除來源為受測 Container 的封包；`syn_ack_packets` 不能當成完整的「出站 SYN-ACK 數」。
- 完成連線數仍是 TCP flags 推測，並未使用 sockops 精準計算三向交握。
- 目前的新來源 IP／flow 欄位並非精確的每秒去重數；模型不使用這兩欄。
- 模型的資料品質檢查主要處理時間窗口問題；尚未接入 BPF map 寫入失敗計數。隨機來源測試增加 map 壓力時，不能僅憑品質欄位判定完全無遺漏。
- `--rand-source` 模擬來源 IP 多樣性，不代表多台獨立攻擊機，也不證明服務已遭資源耗盡。

## 不發流量的驗證

```bash
python3 -m unittest -v test_syn_flood_runtime
bash -n init.sh traffic_test/create_isolated_synlab.sh traffic_test/run_final_holdout_experiment.sh traffic_test/hping3_multi_source.sh
./traffic_test/test_hping3_multi_source.sh
./traffic_test/run_final_holdout_experiment.sh --dry-run
```

進階政策測試需先安裝 `ml_test/requirements.txt`，再執行：

```bash
python -m unittest -v ml_test.test_evaluate_model_policy
```
