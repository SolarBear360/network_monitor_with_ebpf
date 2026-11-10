# syn-window-v1

這是一個「每秒窗口」的 SYN Flood 實驗原型。它接收受保護 Container
在完整一秒內的入站 TCP 統計，輸出攻擊機率。

## 輸入欄位

| 欄位 | 意義 |
|---|---|
| `tcp_packets` | 這一秒收到的入站 TCP 封包數 |
| `tcp_bytes` | 這一秒收到的入站 TCP bytes |
| `syn_only_packets` | 入站且 `SYN=1, ACK=0` 的封包數 |

`syn_ratio = syn_only_packets / tcp_packets` 由 `predict.py` 計算，不需要 eBPF
額外提供。目前模型不使用 SYN-ACK 與完成握手數。

必須使用完整約一秒的 bucket。Map 更新失敗、程式剛啟動或不滿一秒的
bucket 應標為資料品質不良，不要交給模型自動阻擋。

## 安裝與測試

建議先使用與訓練環境相同的版本：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

單筆測試：

```bash
python predict.py \
  --tcp-packets 100 \
  --tcp-bytes 8000 \
  --syn-only-packets 35
```

CSV 批次預測：

```bash
python predict.py \
  --input-csv example_input.csv \
  --output-csv predictions.csv
```

## 輸出解釋

- `attack_probability`：模型輸出的 SYN Flood 機率分數。
- `model_positive`：機率是否至少 `0.5`。
- `alert`：機率至少 `0.5`，且當秒至少有 5 個純 SYN。

這個 `alert` 只是目前實驗的暫定規則。模型只負責輸出判斷，不應直接刪除或
阻擋封包。

## 目前表現與限制

- 用兩輪獨立實驗作整輪交叉驗證：攻擊 precision `1.000`、recall `0.8965`。
- 主要漏判為正常 HTTP 與低速 SYN 同時存在的情境。
- 目前資料來自特定 Mac、Ubuntu、Docker 與局域網實驗，不代表可通用於所有系統。
- 還沒有證明模型告警時服務已出現 backlog 耗盡或 HTTP 失敗。
- 不可以把這份模型的輸出當成正式生產防禦保證。

詳細數值位於 `evaluation/`。

## 與 eBPF userspace 收集器串接

專案內的 `tcpip_stats.py` 已直接使用 `runtime_model.json`。這是從
`model.joblib` 匯出的同一組 Logistic Regression 參數，只需 Python
標準函式庫。程式啟動時載入一次，之後每個完整一秒 bucket 推論一次。

預設狀態規則是機率至少 0.5、當秒至少 5 個純 SYN，且最近
3 秒至少 2 秒符合。進入攻擊狀態後，連續 3 秒正常才解除。
