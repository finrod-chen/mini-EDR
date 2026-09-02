"""Velociraptor API 的薄包裝層。

Velociraptor API 走 mutual TLS(見 deploy/velociraptor/README.md 第 6 節的
`velociraptor config api_client` 步驟),認證用的 CA/私鑰/憑證/連線字串全部
包在 api_client.yaml 裡,由官方 pyvelociraptor 套件負責建立 gRPC channel。

這裡只做兩件事:
1. 讀 api_client.yaml(路徑來自 app.core.config.settings)
2. 把 pyvelociraptor 回傳的「欄位 -> list」格式轉成「一筆一個 dict」的
   list,方便呼叫端逐筆寫入資料庫。
"""

from __future__ import annotations

from typing import Any

import pyvelociraptor
from pyvelociraptor import velo_pandas

from app.core.config import settings


def load_api_config(config_path: str | None = None) -> dict[str, Any]:
    path = config_path or settings.velociraptor_api_config_path
    config: dict[str, Any] = pyvelociraptor.LoadConfigFile(path)
    return config


def query(
    vql: str,
    *,
    config: dict[str, Any] | None = None,
    timeout: int = 600,
    **params: Any,
) -> list[dict[str, Any]]:
    """執行一段 VQL,回傳 list of row dict。

    `config` 可用來在測試/多 org 情境下注入已載入的設定,預設會用
    `load_api_config()` 讀 settings 裡設定的路徑。
    """
    resolved_config = config if config is not None else load_api_config()
    columns: dict[str, list[Any]] = velo_pandas.DataFrameQuery(
        vql, timeout=timeout, config=resolved_config, **params
    )
    if not columns:
        return []

    row_count = len(next(iter(columns.values())))
    return [{col: values[i] for col, values in columns.items()} for i in range(row_count)]
