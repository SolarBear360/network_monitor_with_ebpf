# SYN Flood 基準模型測試

`train_test_syn_flood.py` 用已合併標籤的 `tcp_stats_labeled.csv` 進行：

1. 欄位、缺值、負數、重複時間與標籤檢查。
2. 產生 `syn_ratio = syn_only_packets / tcp_packets`。
3. 切分訓練與測試資料。
4. 比較 Logistic Regression 與 Random Forest。
5. 輸出 ROC-AUC、Attack precision/recall/F1 與混淆矩陣。
6. 保存執行前指定的模型、測試預測和特徵分數。

## 使用的模型特徵

- `tcp_packets`
- `tcp_bytes`
- `syn_only_packets`
- `syn_ratio`

`timestamp`、`run_id` 和 `scenario` 只用來切分與檢查資料，不會交給模型。

## 目前這台 Ubuntu 的執行方式

專案現有的 Anaconda Python 已包含 pandas 與 scikit-learn：

```bash
cd "/home/sean/下載/network_monitor_with_ebpf-main (13)/network_monitor_with_ebpf-main/tcp_ip_stats"

/home/sean/anaconda3/bin/python \
  ml_test/train_test_syn_flood.py \
  --input tcp_stats_labeled.csv
```

輸出會放在：

```text
ml_test/output/
```

- `selected_model.joblib`：預先指定要儲存的完整 Pipeline。
- `evaluation.json`：評估數值、切分方式和警告。
- `test_predictions.csv`：測試集每秒的實際標籤、機率與預測。
- `feature_scores.csv`：兩個模型的特徵係數或重要性。

## 其他環境安裝依賴

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r ml_test/requirements.txt
```

## 多輪實驗

每一輪都保留獨立的已標籤 CSV，然後一次交給程式：

```bash
/home/sean/anaconda3/bin/python \
  ml_test/train_test_syn_flood.py \
  --input \
    collected_runs/run_01.csv \
    collected_runs/run_02.csv \
    collected_runs/run_03.csv \
    collected_runs/run_04.csv \
    collected_runs/run_05.csv
```

當資料包含兩個以上的 `run_id`，程式會把完整的 run 分組留在訓練集或測試集，不會把同一輪的相鄰秒拆到兩邊。

## 只有一輪時的限制

只有一個 `run_id` 時，程式會將各情境依時間切成預設 10 秒的 block，再以 block 分組切分。這比直接隨機拆每一列更保守，但仍然只能驗證：

- CSV 處理正確。
- 模型能完成訓練和預測。
- 標籤和特徵有基本可分性。

不能證明模型對新時間、新機器或新流量情境仍然準確。正式結論至少要收集多個獨立 run。

## 主要參數

```text
--test-size 0.25     測試集比例
--block-size 10      單一 run 時的時間 block 長度
--threshold 0.5      判定 SYN Flood 的機率門檻
--random-state 42    可重現的隨機種子
--save-model logistic_regression
                     要儲存的預先指定模型
```

兩個模型都會被評估，但程式不會根據測試集分數挑選要儲存的模型，以免對測試集產生偏誤。

## 多輪正式訓練與逐輪驗證

`train_multi_round_syn_flood.py` 適合目前一次包含多個 `run_id` 的資料。它會：

1. 檢查是否存在「標成攻擊，但整段完全沒有純 SYN」的可疑情境。
2. 只排除命令列明確指定的失敗情境，不修改原始 CSV。
3. 每次保留完整一輪測試，進行 leave-one-run-out 交叉驗證。
4. 評估完成後，以全部有效資料重新訓練部署模型。

若要實驗性地加入使用者空間估計的完成握手數，可加上：

```text
--include-established-connections
```

若資料是由新版收集器產生，且含有每秒實際有流量的不同來源 IP 數，
可另外加上：

```text
--include-active-source-ips
```

兩個參數可同時使用。舊資料中的 `syn_source_ips` 只統計送出純 SYN 的來源，
和 `active_source_ips` 定義不同，不能當成正式等價資料。

若要實驗「來源 IP 數相對於完成連線數」，可加上：

```text
--include-active-ips-per-established
```

程式會建立
`active_ips_per_established_connection = active_source_ips / (established_connections + 1)`。
分母加 1 是為了讓完成連線數為 0 的時間窗也能推論。這是實驗特徵，
會放大完成連線漏計造成的誤差，不預設啟用。

此欄位可能低估或漏計，應輸出到獨立資料夾，並用未參與訓練的 holdout 比較，不應只看交叉驗證分數。

本次資料的 `run_03_vus70_syn150 / mixed_vus_70_syn_150pps` 在 Mac 上誤走 `utun6`，eBPF 收到的 57 秒資料中純 SYN 全為 0，因此使用以下指令明確排除：

```bash
/home/sean/anaconda3/bin/python \
  ml_test/train_multi_round_syn_flood.py \
  --input tcp_stats_labeled_multi.csv \
  --output-dir ml_test/output_multi_round_final_20261028 \
  --exclude-run-scenario \
    run_03_vus70_syn150 \
    mixed_vus_70_syn_150pps \
  --final-model logistic_regression
```

主要輸出：

- `deployment_model.joblib`：用全部有效資料重新訓練的部署模型。
- `evaluation.json`：逐輪交叉驗證指標。
- `data_quality_report.json`：被排除資料及原因。
- `oof_predictions.csv`：每一秒由「沒有看過該輪」的模型產生的預測。
- `training_data_clean.csv`：保留原始資料、排除失敗情境後的訓練資料副本。

## 小型外部 PCAP 測試

`evaluate_external_pcap.py` 會將 Ethernet/IPv4/TCP PCAP 按目的 IP 整理為每秒特徵，
並直接使用已有的 `deployment_model.joblib` 預測，不會重新訓練模型。

```bash
/home/sean/anaconda3/bin/python \
  ml_test/evaluate_external_pcap.py \
  --benign-pcap CIC-DDoS-2019-Benign.pcap \
  --attack-pcap CIC-DDoS-2019-SynFlood.pcap
```

程式會自動選擇正常 PCAP 中收到最多 TCP 的私有 IP，以及攻擊 PCAP 中收到
最多純 SYN 的私有 IP。如果需要固定目標，可使用 `--benign-target` 和
`--attack-target`。

輸出放在 `ml_test/external_pcap_evaluation/`：

- `external_pcap_predictions.csv`：每秒特徵、機率與預測結果。
- `external_pcap_evaluation.json`：封包檢查、目標 IP、混淆矩陣、指標與限制。

目前 Zenodo 的小型 SYN Flood PCAP 只涵蓋約 0.69 秒，所以只會形成一個攻擊
bucket。這只能當作明顯 SYN 爆量的 sanity check，以及利用較長正常 PCAP 測試
誤報；不能當作統計上可靠的外部準確度。

該正常 PCAP 中自動選擇的 `192.168.50.6` 沒有收到純 SYN，屬於容易的負樣本。
可另外使用會收到低頻正常 SYN 連線與重傳的 `192.168.10.50` 測試困難負樣本：

```bash
/home/sean/anaconda3/bin/python \
  ml_test/evaluate_external_pcap.py \
  --benign-pcap CIC-DDoS-2019-Benign.pcap \
  --attack-pcap CIC-DDoS-2019-SynFlood.pcap \
  --benign-target 192.168.10.50 \
  --output-dir ml_test/external_pcap_evaluation_hard_normal
```

## 完整告警策略測試

`evaluate_model_policy.py` 不會重新訓練模型。它會同時讀取多輪
leave-one-run-out 預測與外部 PCAP 預測，比較：

- 模型機率門檻：`0.5`、`0.7`、`0.9`。
- 當秒最低純 SYN 數：`0`、`2`、`5`、`10`、`20`。
- 持續性規則：單秒、最近 3 秒至少 2 秒、最近 5 秒至少 3 秒。

預設總共比較 45 種策略：

```bash
cd "/home/sean/下載/network_monitor_with_ebpf-main (13)/network_monitor_with_ebpf-main/tcp_ip_stats"

/home/sean/anaconda3/bin/python \
  ml_test/evaluate_model_policy.py
```

輸出放在 `ml_test/comprehensive_policy_evaluation/`：

- `SUMMARY.md`：重點結果與限制的人類可讀摘要。
- `policy_comparison.csv`：每種策略的 FP、FN、precision、recall、F1、
  誤報事件數與攻擊偵測延遲。
- `scenario_breakdown.csv`：各 run/scenario 類型的預測情況。
- `provisional_policy_predictions.csv`：暫定 `probability >= 0.5`、
  `SYN >= 5`、`2-of-3` 規則的每秒詳細結果。
- `comprehensive_evaluation.json`：輸入、資料品質、策略及限制的機器可讀報告。

也可自行改變範圍：

```bash
/home/sean/anaconda3/bin/python \
  ml_test/evaluate_model_policy.py \
  --thresholds 0.4,0.5,0.6,0.7,0.8,0.9 \
  --minimum-syn 0,2,5,10,20,30 \
  --persistence 1/1,2/3,3/5
```

注意：目前外部 SYN Flood PCAP 只有一個攻擊秒，因此可以測試
單秒規則是否抓到明顯攻擊，但不能據此評估 `2-of-3` 或 `3-of-5`
的外部攻擊偵測率。

可另外執行告警規則的單元測試，確認 SYN 下限、K-of-N、時間中斷與
獨立情境的處理沒有壞掉：

```bash
/home/sean/anaconda3/bin/python -m unittest \
  ml_test.test_evaluate_model_policy
```
