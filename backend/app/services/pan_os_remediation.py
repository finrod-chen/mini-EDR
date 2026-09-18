"""封鎖來源 IP 透過 PAN-OS User-ID API 執行(PA-410 syslog 掃描偵測的應變
動作)。

用 User-ID API 動態幫 IP 打 tag(不是 EDL、不是改 policy 物件)——這是
使用者確認的封鎖機制,對應防火牆上要先設好 Dynamic Address Group(比對
這裡打的 tag)+ deny security policy,兩者都是防火牆端的一次性設定,不是
這支模組的範圍。

`<uid-message>` XML 格式跟 `type=user-id` 這個 API 用法是 PAN-OS 官方文件
確認過的標準做法(pan.dev 的 Automating IP Blocking 教學、PAN-OS 官方
Register IP Addresses and Tags Dynamically 文件),`timeout` 屬性
0 = 永久(不自動過期),非 0 = 幾秒後自動解除。

`unblock_ip()`/`list_blocked_ips()` 是解除封鎖清單頁面(app/api/firewall.py)
用的對應函式,分別對應 User-ID API 的 unregister 跟 op command 的
`show object registered-ip all`。
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


def _build_unregister_payload(ip: str, tag: str) -> str:
    # 跟 _build_register_payload 對稱,差別只在 <register> 換成 <unregister>
    # ——PAN-OS User-ID API 的 register/unregister 用同一種 entry+tag+member
    # 結構,不需要 timeout 屬性(那是 register 才有意義的「幾秒後自動過期」
    # 語意,解除封鎖沒有「幾秒後解除」這回事)。
    root = ET.Element("uid-message")
    ET.SubElement(root, "type").text = "update"
    payload = ET.SubElement(root, "payload")
    unregister = ET.SubElement(payload, "unregister")
    entry = ET.SubElement(unregister, "entry")
    entry.set("ip", ip)
    tag_el = ET.SubElement(entry, "tag")
    member = ET.SubElement(tag_el, "member")
    member.text = tag
    return ET.tostring(root, encoding="unicode")


def unblock_ip(ip: str, tag: str) -> str:
    """解除 block_ip() 打上的 tag(User-ID API 的 unregister),回傳 PAN-OS
    原始回應文字(截斷到 2000 字),當 ResponseAction.result 的稽核佐證。
    跟 block_ip 共用同一套輸入驗證/錯誤處理邏輯。"""
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise PanOsApiError(f"不是合法的 IP 位址:{ip}") from exc

    cmd = _build_unregister_payload(ip, tag)
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

    if parsed.get("status") != "success":
        raise PanOsApiError(resp.text[:2000])
    return resp.text[:2000]


_SHOW_REGISTERED_IP_CMD = "<show><object><registered-ip><all/></registered-ip></object></show>"


def list_blocked_ips(tag: str) -> list[dict[str, object]]:
    """列出目前被打上指定 tag 的 registered-ip,對應 CLI `show object
    registered-ip all`(op command,跟 clear_all_registered_ips 同一種
    type=op 用法)。只回傳有掛這個 tag 的條目,給封鎖清單頁面用。

    timeout_seconds 是 PAN-OS 回傳的剩餘秒數(tag member 的 timeout 屬性),
    沒有這個屬性代表是永久或已轉成 persistent,回傳 None——跟
    clear_all_registered_ips() docstring 提到的限制一致,None 不代表這筆
    清得掉。
    """
    try:
        resp = httpx.get(
            f"{settings.panos_api_base_url}/api/",
            params={"type": "op", "cmd": _SHOW_REGISTERED_IP_CMD, "key": settings.panos_api_key},
            timeout=10.0,
            verify=settings.panos_api_verify_tls,
        )
        resp.raise_for_status()
        parsed = ET.fromstring(resp.text)
    except httpx.HTTPError as exc:
        raise PanOsApiError(f"PAN-OS API 連線失敗:{exc}") from exc
    except ET.ParseError as exc:
        raise PanOsApiError(f"PAN-OS API 回應不是合法 XML:{resp.text[:500]}") from exc

    if parsed.get("status") != "success":
        raise PanOsApiError(resp.text[:2000])

    result = parsed.find("result")
    if result is None:
        return []

    blocked: list[dict[str, object]] = []
    for entry in result.findall("entry"):
        ip = entry.get("ip")
        if not ip:
            continue
        for member in entry.findall("./tag/member"):
            if member.text != tag:
                continue
            timeout_attr = member.get("timeout")
            timeout_seconds = int(timeout_attr) if timeout_attr and timeout_attr.isdigit() else None
            blocked.append({"ip": ip, "tag": tag, "timeout_seconds": timeout_seconds})
    return blocked


_CLEAR_REGISTERED_IP_CMD = "<clear><registered-ip><all/></registered-ip></clear>"


def clear_all_registered_ips() -> str:
    """清除所有已註冊的 IP-tag 對應,等同 CLI `debug object registered-ip
    clear all`(op command 的 XML 寫法跟 CLI 版本不一樣,是 PAN-OS 文件
    確認過的對應關係)。

    實機驗證過的重要限制:PAN-OS 對標記為 persistent 的條目,這個指令完全
    沒有效果——官方工程團隊的說法是 persistent 的動態 tag 只有 useridd
    這個系統程序重啟(等同要重開機)才會真的消失。這支函式排程呼叫只能
    清掉非 persistent 的殘留,清不掉 Log Forwarding Built-in Action 這類
    機制產生的 persistent 條目,不能指望它解決容量被塞滿的問題——使用者
    已經被告知這個限制,仍然要求排程執行,所以保留這支函式跟排程,但
    不要誤以為它解決了 persistent 條目的問題。
    """
    try:
        resp = httpx.get(
            f"{settings.panos_api_base_url}/api/",
            params={"type": "op", "cmd": _CLEAR_REGISTERED_IP_CMD, "key": settings.panos_api_key},
            timeout=10.0,
            verify=settings.panos_api_verify_tls,
        )
        resp.raise_for_status()
        parsed = ET.fromstring(resp.text)
    except httpx.HTTPError as exc:
        raise PanOsApiError(f"PAN-OS API 連線失敗:{exc}") from exc
    except ET.ParseError as exc:
        raise PanOsApiError(f"PAN-OS API 回應不是合法 XML:{resp.text[:500]}") from exc

    if parsed.get("status") != "success":
        raise PanOsApiError(resp.text[:2000])
    return resp.text[:2000]
