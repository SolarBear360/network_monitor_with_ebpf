# CICDDoS2019 完整 PCAP：四模型比較

- PCAP 分段：250
- 每秒窗口：5740
- 受保護主機：`192.168.50.1`
- SYN Flood 官方時段：2018-12-01 13:29:00–13:34:00 AST
- 標籤：SYN Flood 時段為 1；其他攻擊類型及背景流量為 0。

## Runtime 政策結果（官方 5 分鐘 SYN 時段）

| 模型 | 特徵 | Accuracy | Balanced accuracy | Precision | Recall | F1 | FP | FN |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `baseline_4` | tcp_packets, tcp_bytes, syn_only_packets, syn_ratio | 97.86% | 92.10% | 76.26% | 85.67% | 80.69% | 80 | 43 |
| `plus_handshake_5` | tcp_packets, tcp_bytes, syn_only_packets, syn_ratio, established_connections | 97.91% | 92.13% | 76.95% | 85.67% | 81.07% | 77 | 43 |
| `plus_active_ip_5` | tcp_packets, tcp_bytes, syn_only_packets, syn_ratio, active_source_ips | 97.91% | 92.13% | 76.95% | 85.67% | 81.07% | 77 | 43 |
| `full_6` | tcp_packets, tcp_bytes, syn_only_packets, syn_ratio, active_source_ips, established_connections | 97.96% | 92.15% | 77.64% | 85.67% | 81.46% | 74 | 43 |

Accuracy 會受大量非 SYN 時段影響，因此選模型時應同時看 Balanced accuracy、Recall、F1、FP 與 FN。

## 排除不確定邊界後的 Runtime 結果

排除 13:29:00–13:29:15 與 13:33:45–13:35:00，共 90 秒。後一段在官方 13:34 結束時間後仍觀察到大量純 SYN，且包含 Runtime 解除告警時間。

| 模型 | Accuracy | Balanced accuracy | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| `baseline_4` | 98.90% | 94.50% | 87.68% | 89.63% | 88.64% | 34 | 28 |
| `plus_handshake_5` | 98.96% | 94.53% | 88.64% | 89.63% | 89.13% | 31 | 28 |
| `plus_active_ip_5` | 98.96% | 94.53% | 88.64% | 89.63% | 89.13% | 31 | 28 |
| `full_6` | 99.01% | 94.55% | 89.63% | 89.63% | 89.63% | 28 | 28 |

## 限制

- `active_source_ips` 由 PCAP 中每秒入站 TCP 的不同來源 IP 重建，與 eBPF map 的實作可能有些微差異。
- `established_connections` 由觀察到的 SYN、SYN-ACK、最終 ACK 重建；遺失封包時會低估。
- 官方時程只有分鐘精度，因此另提供排除 90 秒不確定開始、結束與告警冷卻區間的 trimmed-core 結果。
- 這是跨環境外部測試，不取代實驗室的獨立 holdout。
