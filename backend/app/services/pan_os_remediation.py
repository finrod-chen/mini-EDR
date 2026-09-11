"""封鎖來源 IP 透過 PAN-OS User-ID API 執行(PA-410 syslog 掃描偵測的應變
動作)。

用 User-ID API 動態幫 IP 打 tag(不是 EDL、不是改 policy 物件)——這是
使用者確認的封鎖機制,對應防火牆上要先設好 Dynamic Address Group(比對
這裡打的 tag)+ deny security policy,兩者都是防火牆端的一次性設定,不是
這支模組的範圍。

`<uid-message>` XML 格式跟 `type=user-id` 這個 API 用法是 PAN-OS 官方文件
確認過的標準做法(pan.dev 的 Automating IP Blocking 教學、PAN-OS 官方
Register IP Addresses and Tags Dynamically 文件),`timeout` 屬性
0 = 永久(不自動過期),非 0 = 幾秒後自動解除——這裡預設永久,因為封鎖是
人工確認後才觸發的動作(不是自動封鎖),要解除的話目前只能去 PAN-OS 自己
的介面手動操作,沒有另外做「解除封鎖」按鈕(不在這次範圍內)。
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET

import httpx

from app.core.config import settings


class PanOsApiError(Exception):
    """PAN-OS User-ID API 呼叫失敗,或目標不是合法 IP。"""


def _build_register_payload(ip: str, tag: str, timeout_seconds: int) -> str:
    # 用 ElementTree 組 XML,不是 f-string 字串接——ip 這個值來自 syslog
    # 解析出的 alert.host,雖然理論上一定是防火牆填入的合法 IP,但邊界
    # 輸入不能盲信,尤其接下來要塞進 XML 屬性值,f-string 接法會有注入風險
    # (ElementTree 自動處理跳脫)。
    root = ET.Element("uid-message")
    ET.SubElement(root, "type").text = "update"
    payload = ET.SubElement(root, "payload")
    register = ET.SubElement(payload, "register")
    entry = ET.SubElement(register, "entry")
    entry.set("ip", ip)
    tag_el = ET.SubElement(entry, "tag")
    member = ET.SubElement(tag_el, "member")
    member.set("timeout", str(timeout_seconds))
    member.text = tag
    return ET.tostring(root, encoding="unicode")


def block_ip(ip: str, tag: str, timeout_seconds: int = 0) -> str:
    """回傳 PAN-OS API 的原始回應文字(截斷到 2000 字),當 ResponseAction.result
    的稽核佐證,比照 velociraptor_remediation._result_to_json 的做法。"""
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise PanOsApiError(f"不是合法的 IP 位址:{ip}") from exc

    cmd = _build_register_payload(ip, tag, timeout_seconds)
    try:
        resp = httpx.post(
            f"{settings.panos_api_base_url}/api/",
            params={"type": "user-id", "key": settings.panos_api_key},
            data={"cmd": cmd},
            timeout=10.0,
            verify=settings.panos_api_verify_tls,
        )
        resp.raise_for_status()
        parsed = ET.fromstring(resp.text)
    except httpx.HTTPError as exc:
        raise PanOsApiError(f"PAN-OS API 連線失敗:{exc}") from exc
    except ET.ParseError as exc:
        raise PanOsApiError(f"PAN-OS API 回應不是合法 XML:{resp.text[:500]}") from exc

    # 用回應的 status 屬性判斷成敗,不是對回應文字做子字串比對——錯誤訊息
    # 裡剛好包含 "success" 這個詞的機率雖然低,但屬性讀取才是正確做法。
    if parsed.get("status") != "success":
        raise PanOsApiError(resp.text[:2000])
    return resp.text[:2000]
