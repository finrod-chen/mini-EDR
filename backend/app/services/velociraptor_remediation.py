"""應變動作(隔離主機/砍進程)透過 Velociraptor API 執行(Phase 5)。

呼叫的是官方 `collect_client()` server VQL plugin,在指定 client 上排一個
新的 artifact collection
(https://docs.velociraptor.app/vql_reference/server/collect_client/)。

注意:pyvelociraptor 的 VQL env 參數(見 app/services/velociraptor_client.py
底層用的 `velo_pandas.DataFrameQuery`)只能傳字串,不能直接傳 Python dict
或 bool 當參數值——所以 `Windows.Remediation.Process` 需要的
`spec=dict(...)` 巢狀結構跟 `ReallyDoIt=TRUE` 這個 bool 常數,都直接寫死在
VQL 查詢字串裡面,只有 PidRegex 這種字串值走 env 參數帶進去(跟
app/services/evtx_hunt.py 的 hunt() 用法是同一個限制、同一套處理方式)。

回傳值裡刻意不去精確解析 flow_id——官方文件不同範例對 collect_client()
回傳欄位的說法不完全一致(有的範例是 `.request AS Flow`,有的直接
`AS Flow` 再讀 `flow_id`),沒有實機測過,不確定哪個是對的,索性整包原始
回應記錄進 response_actions.result 當稽核佐證就好,要追查細節時去
Velociraptor GUI 查該 client 的 flow 紀錄即可。
"""

from __future__ import annotations

import json

from app.services import velociraptor_client

QUARANTINE_ARTIFACT = "Windows.Remediation.Quarantine"

# Windows.Remediation.Process 屬於 Velociraptor Artifact Exchange 的內容,
# 不是內建 artifact,第一次用之前要先在 GUI 匯入,見
# deploy/velociraptor/README.md 第 9 節,否則這裡會直接失敗。
KILL_PROCESS_ARTIFACT = "Windows.Remediation.Process"

_QUARANTINE_VQL = """
SELECT collect_client(
    client_id=ClientId,
    artifacts=[Artifact]
) AS Result
FROM scope()
"""

_KILL_PROCESS_VQL = """
SELECT collect_client(
    client_id=ClientId,
    artifacts=[Artifact],
    spec=dict(`Windows.Remediation.Process`=dict(
        PidRegex=PidRegex,
        ReallyDoIt=TRUE
    ))
) AS Result
FROM scope()
"""


class ClientNotFoundError(Exception):
    """指定的 hostname 在 Velociraptor 裡找不到對應的 client_id。"""


def resolve_client_id(hostname: str) -> str:
    rows = velociraptor_client.query(
        "SELECT client_id FROM clients(search=Hostname) LIMIT 1", Hostname=hostname
    )
    if not rows:
        raise ClientNotFoundError(f"找不到 hostname={hostname} 對應的 Velociraptor client")
    return str(rows[0]["client_id"])


def _result_to_json(rows: list[dict[str, object]]) -> str:
    result = rows[0]["Result"] if rows else {}
    return json.dumps(result, ensure_ascii=False, default=str)[:2000]


def quarantine_host(hostname: str) -> str:
    client_id = resolve_client_id(hostname)
    rows = velociraptor_client.query(
        _QUARANTINE_VQL, ClientId=client_id, Artifact=QUARANTINE_ARTIFACT
    )
    return _result_to_json(rows)


def kill_process(hostname: str, pid: int) -> str:
    client_id = resolve_client_id(hostname)
    rows = velociraptor_client.query(
        _KILL_PROCESS_VQL,
        ClientId=client_id,
        Artifact=KILL_PROCESS_ARTIFACT,
        PidRegex=f"^{pid}$",
    )
    return _result_to_json(rows)
