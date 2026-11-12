# 低速 SYN 邊界實驗分析

- 使用模型：`ml_test/output_comprehensive_runs_1_and_3_20261108/deployment_model.joblib`
- 有效逐秒資料：880 秒（正常 281、明確攻擊對照 106、診斷 493）
- 已知標籤對照：TN=281, FP=0, FN=0, TP=106
- 5–40 pps 混合情境保持 `label=-1`，未拿來重新訓練。

## 10 VUs + 低速 SYN

| scenario | 實際純 SYN/秒平均 | 機率中位數 | 告警秒數/總秒數 | HTTP 失敗率 | HTTP p95 |
|---|---:|---:|---:|---:|---:|
| diagnostic_mixed_10vus_syn_5pps | 4.85 | 0.010 | 0/41 | 0.00% | 7.66 ms |
| diagnostic_mixed_10vus_syn_10pps | 9.50 | 0.031 | 0/42 | 0.00% | 7.60 ms |
| diagnostic_mixed_10vus_syn_15pps | 14.00 | 0.080 | 0/44 | 0.00% | 6.38 ms |
| diagnostic_mixed_10vus_syn_20pps | 18.14 | 0.173 | 0/44 | 0.00% | 5.49 ms |
| diagnostic_mixed_10vus_syn_25pps | 21.87 | 0.307 | 3/47 | 0.00% | 5.52 ms |
| diagnostic_mixed_10vus_syn_30pps | 26.09 | 0.504 | 24/47 | 0.00% | 5.98 ms |
| diagnostic_mixed_10vus_syn_35pps | 29.73 | 0.761 | 48/48 | 0.00% | 148.49 ms |
| diagnostic_mixed_10vus_syn_40pps | 32.06 | 0.803 | 51/51 | 0.00% | 10.53 ms |

## 解讀

- 模型在混合正常流量下呈現連續的機率變化，並非存在一條天然正確的 SYN Flood 分界。
- 這輪所有混合情境 HTTP 失敗率都是 0%，所以只能研究模型判斷邊界，不能證明服務已耗盡。
- 35 pps 的延遲曾明顯升高，但 40 與 70 pps 又下降，並非隨 SYN 速率單調惡化，不能只憑單次結果歸因於攻擊。
- 下一步應先定義標籤：要偵測「惡意純 SYN 行為」，或偵測「已對服務造成資源壓力的 Flood」。兩者需要不同 ground truth。
