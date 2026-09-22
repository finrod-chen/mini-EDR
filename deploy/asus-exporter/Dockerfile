# 改用 python:3.12-slim,跟 backend/Dockerfile 同一個 base image——上游原本
# 用 python:3.13-rc-alpine3.20(release candidate,不適合長期跑在 NAS
# 上),而且 requirements.txt 已經砍到只剩 requests/prometheus_client 兩個
# 純 Python 套件,不需要 alpine 版額外裝 gcc/libc-dev 編譯 C extension。
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt asus-exporter.py /app/

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "asus-exporter.py"]
