# 流量測試腳本

目前使用 Ubuntu 單機、隔離 Docker 網路及 hping3 Container 的 final holdout 流程。

請依照 [FINAL_HOLDOUT_USAGE.md](FINAL_HOLDOUT_USAGE.md) 建立受測 Container、啟動 eBPF 與 CSV 收集器，再執行測試。

- `create_isolated_synlab.sh`：建立隔離環境。
- `run_final_holdout_experiment.sh`：完整實驗、標籤合併與模型評估。
- `normal_tcp_connections.py`、`normal_http_keepalive.py`：正常 HTTP 流量。
- `hping3_multi_source.sh`、`hping3.Dockerfile`：主腳本使用的 hping3 工具。
- `merge_labels.py`：按實際情境時間合併標籤。

舊 Mac／Nping／k6 流程不在本分支的交付範圍。`results/` 由執行時產生，Git 會忽略其中的資料。
