# 改用 python:3.12-slim,跟 backend/Dockerfile 同一個 base image——上游原本
# 用 python:3.13-rc-alpine3.20(release candidate,不適合長期跑在 NAS
# 上),而且 requirements.txt 已經砍到只剩 requests/prometheus_client 兩個
# 純 Python 套件,不需要 alpine 版額外裝 gcc/libc-dev 編譯 C extension。
FROM python:3.12-slim

# 容器裡的 stdout 不是接到 terminal,Python 預設走 block buffering,
# print() 的內容不會即時寫出來,`docker compose logs` 會長時間看起來
# 空白(要等 buffer 滿或 process 結束才 flush)。asus-exporter.py 的
# login_router() 失敗訊息、health_check() 的錯誤都是靠 print(),不設這個
# 的話出問題時完全看不到任何線索。
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt asus-exporter.py /app/

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "asus-exporter.py"]
