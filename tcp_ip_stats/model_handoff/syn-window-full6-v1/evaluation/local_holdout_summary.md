# 獨立 final holdout 測試結果

這份資料只用於最後評估，不得重新加入訓練。

- 有效秒數：2737
- Accuracy：0.9266
- 攻擊 Precision：0.9851
- 攻擊 Recall：0.8903
- 攻擊 F1：0.9353
- Confusion matrix：{'tn': 1084, 'fp': 22, 'fn': 179, 'tp': 1452}
- 攻擊情境偵測：15/16

限制：多來源 IP 是同一台主機的 hping3 Container 所產生，不是多台獨立實體攻擊機。
