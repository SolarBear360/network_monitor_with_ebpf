# syn-window-full6-v1

這是目前專案指定的最終六特徵模型（`full_6`）。模型以約一秒的統計窗口為
一筆輸入，輸出該窗口屬於 SYN Flood 的機率；`tcpip_stats.py` 已預設載入
本資料夾的 `runtime_model.json`。

## 六個模型特徵

| 特徵 | 來源與意義 |
|---|---|
| `tcp_packets` | 這一秒收到的入站 TCP 封包數 |
| `tcp_bytes` | 這一秒收到的入站 TCP bytes |
| `syn_only_packets` | 入站且 `SYN=1, ACK=0` 的封包數 |
| `syn_ratio` | `syn_only_packets / tcp_packets`，由 userspace 計算 |
| `active_source_ips` | 本輪確實有新增入站 TCP 封包的不同來源 IP 數 |
| `established_connections` | 本輪第一次觀察到進入 `ESTABLISHED` 的 flow 數 |

eBPF/userspace 需要直接提供五個原始值；`syn_ratio` 由
`syn_flood_runtime.py` 自動計算，不需要額外在 kernel 中維護。

## 正式 runtime 政策

- 模型機率門檻：`0.5`
- 當秒最少純 SYN：`5`
- 最近 `3` 個有效窗口中至少 `2` 個異常才進入 `ATTACK`
- 連續 `3` 個正常窗口後解除 `ATTACK`
- 有效窗口長度：`0.8` 到 `1.2` 秒

第一次掃描、時間不足一秒或品質不良的窗口不會拿來改變告警狀態。

## 檔案用途

- `runtime_model.json`：實際由 root userspace 程式載入的輕量模型參數。
- `syn_flood_runtime.py`：只使用 Python 標準函式庫的推論與狀態機。
- `model.joblib`：完整 scikit-learn 訓練產物，供重現及離線分析。
- `model_manifest.json`：版本、特徵、門檻、雜湊與評估摘要。
- `evaluation/`：本地獨立 holdout、外部 CICDDoS2019 PCAP 與特徵分數。

## 目前驗證結果

- 本地獨立 final holdout（完整 runtime 政策）：Accuracy `92.66%`、
  Precision `98.51%`、Recall `89.03%`、F1 `93.53%`。
- CICDDoS2019 完整 PCAP 官方五分鐘標籤：Accuracy `97.96%`、F1 `81.46%`。
- 排除官方分鐘標籤的開始／結束不確定邊界後：Accuracy `99.01%`、
  F1 `89.63%`。

這些結果是實驗原型的量測，不代表可直接用於正式生產環境；模型告警也不應
直接觸發永久封鎖。
