# 模型訓練與評估工具

以下命令均從 `tcp_ip_stats` 目錄執行。

| 程式 | 用途 |
|---|---|
| `evaluate_final_holdout.py` | 讀取新收集的獨立測試資料，評估凍結 runtime 模型；由 final holdout 腳本自動呼叫 |
| `evaluate_model_policy.py` | 對已有預測機率比較不同告警政策 |
| `test_evaluate_model_policy.py` | 政策評估的單元測試 |
| `evaluate_external_pcap.py` | 從外部 PCAP 轉換統計並評估模型；PCAP 需自行取得 |
| `train_test_syn_flood.py` | 從標記資料訓練並測試模型 |
| `train_multi_round_syn_flood.py` | 多輪實驗訓練與依整輪分組評估；會引用 `train_test_syn_flood.py` |

## 套件

`evaluate_final_holdout.py` 與即時 runtime 使用標準函式庫。其他訓練與進階分析工具需要：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r ml_test/requirements.txt
python -m unittest -v test_syn_flood_runtime ml_test.test_evaluate_model_policy
```

若要使用已凍結的 `model.joblib`，原訓練套件版本記錄於 `model_handoff/syn-window-v1/requirements.txt`；joblib/sklearn 的載入可能受版本影響。即時 runtime JSON 不依賴 sklearn。

## 重新評估已完成的一輪

```bash
# 將路徑換成該輪實驗實際輸出位置
python3 ml_test/evaluate_final_holdout.py \
  --input traffic_test/results/final_holdout_YYYYMMDD_HHMMSS/final_holdout_labeled.csv \
  --runtime-model model_handoff/syn-window-v1/runtime_model.json \
  --output-dir traffic_test/results/final_holdout_YYYYMMDD_HHMMSS/evaluation
```

輸出為 `SUMMARY.md`、`evaluation.json`、`scenario_summary.csv`、`predictions.csv`。
最後評估資料不可加入訓練；其標籤代表測試情境，不等於服務已崩潰。

## 訓練與外部資料

原始訓練資料、歷史預測 CSV 與大型 PCAP 未上傳。某些程式的預設輸入路徑指向先前實驗輸出，必須換成自己實際持有的檔案。執行前使用各程式 `--help` 查閱必要參數：

```bash
python ml_test/train_test_syn_flood.py --help
python ml_test/train_multi_round_syn_flood.py --help
python ml_test/evaluate_external_pcap.py --help
python ml_test/evaluate_model_policy.py --help
```

外部 PCAP 的統計方式與本機 eBPF 觀測點可能不同，不能把其分數直接當成實際部署的準確率。
