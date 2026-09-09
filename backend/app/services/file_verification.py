"""單一可疑檔案的類型驗證(告警調查用,見 app/api/alerts.py 的 verify_file action)。

只針對分析師指定的單一檔案做，不是全端點掃描——設計理由見規劃討論:全磁碟
掃描的 hunt 成本、跟現有告警規則的關聯性都不划算,只在「調查某個可疑
process image path」這種明確情境下才觸發。

流程(每一步都在 2026-09-09 於 NAS 實機上跟使用者一起驗證過,不是照文件猜的):

1. `collect_client()` 對指定 hostname 觸發 `Generic.Collectors.File`,把單一
   檔案收集回 Server。`collectionSpec` 參數收到的是 CSV 文字(一欄 `Glob`),
   而且最終掃描路徑是 `pathspec(Path=Root) + Glob` 字串相接——所以 `Glob`
   只能放「相對於 Root 磁碟代號」的路徑,不能重複帶一次磁碟代號,否則會變成
   `C:\\C:\\...` 這種不存在的路徑而完全掃不到東西(GUI 上測 notepad.exe/
   win.ini 都撞過這個)。
2. `collect_client()` 是非同步的,輪詢 `Generic.Collectors.File/Uploads` 這個
   source 直到出現結果為止(跟 app/jobs/sync_assets.py 的
   `_launch_and_poll_hunt` 同樣的道理)。
3. 用官方 `VFSGetBuffer` gRPC API(不是 `pyvelociraptor.velo_pandas` 走的一般
   VQL 查詢通道)把上傳的檔案內容讀回來——實測過一般 VQL 配
   `file_store()`+`read_file()` 讀到的是 Velociraptor 內部儲存格式的原始
   位元組,SHA256 對不起來,不能用來判斷真實檔案類型。上傳檔案的 vfs 路徑
   組成方式(`clients/<client_id>/collections/<flow_id>/uploads/<accessor>/
   <原始路徑逐段>`)官方文件沒有清楚記載,是從 GUI 下載連結的
   `fs_components` 參數反推確認的。
4. 讀回內容後先用 `Uploads` 記錄的 SHA256 自我核對一次(防止 gRPC 分段讀取
   中間出錯而不自知),再交給 Magika 判斷真實類型,跟宣稱的副檔名比對。
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
import time
from dataclasses import dataclass
from typing import Any

import grpc
from magika import Magika
from pyvelociraptor import api_pb2, api_pb2_grpc

from app.services import velociraptor_client
from app.services.velociraptor_remediation import resolve_client_id

COLLECT_ARTIFACT = "Generic.Collectors.File"
ACCESSOR = "auto"

# collect_client()/kill_process 的既有限制同樣適用:artifact 名稱要寫死成
# 字面量,不能走 VQL env 變數帶進去,否則 Velociraptor 的 ACL 檢查會直接
# 靜默回傳 NULL(見 app/services/velociraptor_remediation.py 開頭的說明)。
_COLLECT_VQL = f"""
SELECT collect_client(
    client_id=ClientId,
    artifacts=['{COLLECT_ARTIFACT}'],
    spec=dict(`{COLLECT_ARTIFACT}`=dict(
        collectionSpec=CollectionSpec,
        Root=Root,
        Accessor='{ACCESSOR}'
    ))
) AS Result
FROM scope()
"""

_UPLOADS_VQL = f"""
SELECT SourceFile, FileSize, SourceFileSha256
FROM source(client_id=ClientId, flow_id=FlowId, artifact='{COLLECT_ARTIFACT}/Uploads')
"""

_WINDOWS_ABS_PATH = re.compile(r"^([A-Za-z]):(\\.+)$")


class InvalidPathError(Exception):
    """不是合法的 Windows 絕對路徑(例如缺少磁碟代號)。"""


class FileNotFoundOnClientError(Exception):
    """在時限內沒有收到檔案——路徑打錯、檔案不存在、或端點離線都會導致這個結果。"""


class UploadIntegrityError(Exception):
    """VFSGetBuffer 讀回的內容雜湊值跟 Velociraptor 記錄的不符,內容可能已損壞。"""


@dataclass
class ClassificationResult:
    declared_path: str
    file_size: int
    sha256: str
    detected_label: str
    detected_mime_type: str
    detected_extensions: list[str]
    extension_mismatch: bool


def _split_root_and_glob(path: str) -> tuple[str, str]:
    match = _WINDOWS_ABS_PATH.match(path.strip())
    if not match:
        raise InvalidPathError(f"不是合法的 Windows 絕對路徑:{path!r}(需要類似 C:\\... 的格式)")
    drive, rest = match.groups()
    return f"{drive}:", rest


def _build_collection_spec_csv(glob: str) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(["Glob"])
    writer.writerow([glob])
    return buffer.getvalue()


def _launch_collection(client_id: str, root: str, glob: str) -> str:
    rows = velociraptor_client.query(
        _COLLECT_VQL,
        ClientId=client_id,
        CollectionSpec=_build_collection_spec_csv(glob),
        Root=root,
    )
    result = rows[0]["Result"] if rows else {}
    flow_id = result.get("FlowId") if isinstance(result, dict) else None
    if not flow_id:
        raise RuntimeError(f"collect_client() 沒有回傳 FlowId:{result!r}")
    return str(flow_id)


def _poll_upload(
    client_id: str, flow_id: str, *, timeout: float = 60.0, poll_interval: float = 3.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        rows = velociraptor_client.query(_UPLOADS_VQL, ClientId=client_id, FlowId=flow_id)
        if rows:
            return rows[0]
        if time.monotonic() >= deadline:
            raise FileNotFoundOnClientError(
                "在時限內沒有收到檔案,請確認路徑是否正確、檔案是否存在、端點是否在線"
            )
        time.sleep(poll_interval)


def _fetch_uploaded_bytes(client_id: str, flow_id: str, path: str) -> bytes:
    components = [
        "clients",
        client_id,
        "collections",
        flow_id,
        "uploads",
        ACCESSOR,
        *path.replace("\\", "/").split("/"),
    ]
    config = velociraptor_client.load_api_config()
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"),
    )
    options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)

    content = bytearray()
    with grpc.secure_channel(config["api_connection_string"], creds, options) as channel:
        stub = api_pb2_grpc.APIStub(channel)
        offset = 0
        chunk_size = 65536
        while True:
            request = api_pb2.VFSFileBuffer(
                org_id="root", components=components, length=chunk_size, offset=offset
            )
            response = stub.VFSGetBuffer(request)
            if not response.data:
                break
            content.extend(response.data)
            offset += len(response.data)
    return bytes(content)


_magika = Magika()


def verify_file(hostname: str, path: str) -> ClassificationResult:
    """觸發收集、讀回內容、用 Magika 分類,回傳分類結果。

    這是唯讀調查動作,不對端點做任何變更(不像 quarantine/kill_process 會
    改變端點狀態),但呼叫端(app/api/alerts.py)目前跟其他動作共用同一個
    require_admin 端點,權限層級一致,沒有另外放寬。
    """
    root, glob = _split_root_and_glob(path)
    client_id = resolve_client_id(hostname)

    flow_id = _launch_collection(client_id, root, glob)
    upload_row = _poll_upload(client_id, flow_id)

    content = _fetch_uploaded_bytes(client_id, flow_id, path)
    actual_sha256 = hashlib.sha256(content).hexdigest()

    expected_sha256 = str(upload_row.get("SourceFileSha256") or "")
    if expected_sha256 and actual_sha256 != expected_sha256:
        raise UploadIntegrityError(
            f"讀回內容的 SHA256({actual_sha256})與 Velociraptor 記錄的"
            f"({expected_sha256})不符"
        )

    magika_result = _magika.identify_bytes(content)
    declared_ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    detected_extensions = list(magika_result.output.extensions)

    return ClassificationResult(
        declared_path=path,
        file_size=len(content),
        sha256=actual_sha256,
        detected_label=magika_result.output.label,
        detected_mime_type=magika_result.output.mime_type,
        detected_extensions=detected_extensions,
        extension_mismatch=bool(declared_ext) and declared_ext not in detected_extensions,
    )
