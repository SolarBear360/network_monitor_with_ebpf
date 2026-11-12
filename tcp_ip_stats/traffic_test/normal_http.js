import http from "k6/http";
import { check, sleep } from "k6";

/*
 * 正常 HTTP 使用者流量。
 *
 * 實驗參數（VU 數量、時間、是否重用連線）由
 * run_experiment.sh 透過 k6 命令列選項控制。
 */
export const options = {
    discardResponseBodies: true,
};

export default function () {
    const targetUrl = __ENV.TARGET_URL;

    if (!targetUrl) {
        throw new Error("TARGET_URL 未設定");
    }

    const response = http.get(targetUrl, {
        tags: { traffic_kind: "legitimate_http" },
        timeout: "5s",
    });

    check(response, {
        "HTTP status is below 400": (res) => res.status < 400,
    });

    // 讓每個虛擬使用者不是無間隔地連續發送請求。
    sleep(0.2 + Math.random() * 0.8);
}
