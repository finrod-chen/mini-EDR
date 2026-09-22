# vendor 自 https://github.com/LaurentDumont/asus-router-exporter
# commit 8fd39180f21e2c0907a273ef8ad916d9e4fe0200(asus-exporter.py,原始檔名相同)。
# 上游 repo 沒有附 LICENSE 檔(預設保留著作權),這裡是個人/內部使用,
# 不對外散布。如果要更新版本,直接對照上游同一個檔案重新複製,沒有自動
# 同步機制,見 deploy/asus-exporter/README.md。
#
# 跟上游的差異(部署到這個專案的 3 台實機後陸續補的,都是對症下藥,不是
# 重寫;其餘邏輯照原樣保留):
# 1. login_router() 原本寫死 `http://{ip}/login.cgi`,假設 exporter 跟
#    路由器在同一個 LAN、路由器的網頁管理介面走預設的 HTTP:80。這個專案
#    的部署情境是 exporter 只能從路由器的 WAN 端(其實是內部管理網段,見
#    README)存取,ASUS 韌體的「Enable Web Access from WAN」只開放 HTTPS
#    + 自訂 port(預設 8443)、自簽憑證,所以改成可設定的 scheme/port
#    (ASUS_SCHEME/ASUS_PORT,見下面 login_router()),並且對 requests
#    關閉憑證驗證(自簽憑證,跟這個專案對 PAN-OS API 的既有安全假設一致,
#    見 backend/app/core/config.py 的 panos_api_verify_tls)。
# 2. parse_payload() 的 CPU 解析原本無條件對 cpu1~cpu4 四個變數呼叫
#    .set(),但少於 4 核心的機型(實測 RT-AX82U)回應裡根本不會有
#    cpu3/cpu4 的資料,迴圈結束後這兩個變數從沒被賦值,直接
#    UnboundLocalError。改成沒抓到的核心明確 set 成 NaN(不是 0.0——
#    0.0 沒辦法分辨「真的閒置」還是「這顆核心不存在」)。
# 3. uptime 的解析原本整段丟給 json.loads(),但這個 hook 回的不是嚴格
#    JSON(日期字串沒加引號,實測至少一款韌體是這樣——這些 hook 本來是
#    給網頁前端 eval() 當 JS 物件字面值用的,不保證是合法 JSON),改成
#    直接用 regex 從原始文字撈「(N secs since boot)」這段。
# 4. get_clientlist() 的每個裝置原本無條件 float(curRx)/float(curTx)、
#    int(wlConnectTime 切出來的每一段),但實測(RT-AX1800HP 386_68691)
#    這幾個欄位常常是空字串,一撞到就整個 hook 從第一台裝置開始全部中斷
#    處理。改成缺值就設 NaN/略過,不影響其他裝置——這支 exporter 只拿
#    active_device 的 mac_address 標籤去數連線裝置數,不看這幾個欄位的
#    實際數值。

from time import sleep
import requests
import base64
from os import getenv
import json
from prometheus_client import start_http_server, Gauge
from re import sub, compile, findall, search

# 自簽憑證會讓 requests 每次請求都印一次 InsecureRequestWarning,關掉
# verify 後這個警告本來就是預期中的雜訊,不用讓它洗版 log。
requests.packages.urllib3.disable_warnings(  # type: ignore[attr-defined]
    requests.packages.urllib3.exceptions.InsecureRequestWarning  # type: ignore[attr-defined]
)


#data total = {
#"memory_usage":"mem_total":"524288","mem_free":"134976","mem_used":"389312"
#}

#{
#"cpu_usage":"cpu1_total":"169547880","cpu1_usage":"979847","cpu2_total":"169551396","cpu2_usage":"1014974","cpu3_total":"169557418","cpu3_usage":"1100618","cpu4_total":"169538192","cpu4_usage":"1294285"
#}

uptime_metric = Gauge('uptime', 'Uptime of the router')
memory_total_metric = Gauge('memory_total', 'Total memory of the router')
memory_free_metric = Gauge('memory_free', 'Free memory of the router')
memory_used_metric = Gauge('memory_used', 'Used memory of the router')
cpu1_percent_metric = Gauge('cpu1_percent', 'CPU1 usage of the router')
cpu2_percent_metric = Gauge('cpu2_percent', 'CPU2 usage of the router')
cpu3_percent_metric = Gauge('cpu3_percent', 'CPU3 usage of the router')
cpu4_percent_metric = Gauge('cpu4_percent', 'CPU4 usage of the router')
active_device_metric = Gauge('active_device', 'Active devices connected to the router', ['ip_address', 'device_name', 'connection_type', 'metric', 'mac_address'])
wan_status = Gauge('wan_information', 'WAN information', ['wan_status', 'wan_type','wan_ip', 'wan_netmask', 'wan_gateway', 'wan_dns'])
wan_lease = Gauge('wan_lease', 'Length of the lease in seconds')
wan_expires = Gauge('wan_expires', 'Time when the lease expires in seconds')


# Thank you to our benevolent AI overlords for this regex
def parse_wanlink_status(wanlink_status_str):
    pattern = compile(r"function\s+(\w+)\(\)\s+\{\s+return\s+([^;]+);")
    matches = pattern.findall(wanlink_status_str)

    wanlink_status = {}
    for match in matches:
        key, value = match
        if value.isdigit():
            wanlink_status[key] = int(value)
        elif value.replace('.', '').isdigit():
            wanlink_status[key] = value
        else:
            wanlink_status[key] = value.strip("'")

    # We clear the metrics before setting them to avoid stale data
    # TO-DO More elegant solution to prevent creating a new Gauge because of the label changing value
    wan_status.clear()
    wan_status.labels(wanlink_status['wanlink_status'],
                      wanlink_status['wanlink_type'],
                      wanlink_status['wanlink_ipaddr'],
                      wanlink_status['wanlink_netmask'],
                      wanlink_status['wanlink_gateway'],
                      wanlink_status['wanlink_dns'],
                      ).set(float(4242))
    wan_lease.set(float(wanlink_status['wanlink_lease']))
    wan_expires.set(float(wanlink_status['wanlink_expires']))

def health_check():
    # check if all env variables are set
    if getenv('ASUS_USERNAME') is None:
        print("ASUS_USERNAME is not set")
        exit(1)
    if getenv('ASUS_PASSWORD') is None:
        print("ASUS_PASSWORD is not set")
        exit(1)
    if getenv('ASUS_IP') is None:
        #check if the IP is just an IP
        if getenv('ASUS_IP').count('.') != 3:
            print("ASUS_IP is not set")
            exit(1)
        print("ASUS_IP is not set")
        exit(1)

def sanitize_string(data):
    #remove all non-numeric characters
    return sub(r"\D", "", data)

def safe_float(value):
    # get_clientlist() 有些欄位(curRx/curTx/wlConnectTime,實測至少在
    # RT-AX1800HP 386_68691 這個韌體版本上)會是空字串而不是數字——這支
    # exporter 只拿這些欄位去算連線裝置數(見 backend 的
    # sync_asus_exporter.py,不看實際的 RX/TX 數值),缺值時用 NaN 代表
    # 「這個裝置沒有回報這個指標」,不要讓一整個 get_clientlist 因為一個
    # 空欄位就整批處理中斷(上游原本沒有這層防禦,直接 float('') 炸掉)。
    try:
        return float(value)
    except (TypeError, ValueError):
        return float('nan')

def parse_payload(payload):
    #print(payload)

    if "cpu_usage" in payload:
        sanitized_format_cpu = payload.split(',')

        # 上游原本沒初始化這四個變數,雙核心(或核心數 < 4)的機型回應裡
        # 根本不會有 cpu3_*/cpu4_* 的資料,迴圈結束後這兩個變數從沒被
        # 賦值過,下面卻無條件呼叫 .set(),直接 UnboundLocalError 炸掉
        # ——這是這次 vendor 進來時修的 bug,不是上游原本就有初始化再被
        # 我們拿掉。改成 None 起始值,迴圈結束後沒抓到的核心明確 set 成
        # NaN(不是 0.0)——Gauge 沒被 set 過的話 Prometheus 預設值就是
        # 0.0,如果只是跳過不 set,消費端(backend 的 sync_asus_exporter.py)
        # 從 /metrics 讀到的還是 0.0,沒辦法分辨「這顆核心真的閒置在
        # 0%」還是「這台路由器根本沒有第 3/4 顆核心」,算平均值會被拉低。
        # NaN 才是明確的「這個維度不適用」訊號,見 sync_asus_exporter.py
        # 的 _build_metrics() 怎麼過濾。
        cpu1_percent = cpu2_percent = cpu3_percent = cpu4_percent = None
        for data in sanitized_format_cpu:
            try:
                if "cpu1_total" in data:
                    #We use sub to remove all non-numeric characters
                    cpu1_total = sanitize_string(data.split(':')[2])
                elif "cpu1_usage" in data:
                    cpu1_usage = sanitize_string(data.split(':')[1])
                    cpu1_percent = (float(cpu1_usage) / float(cpu1_total)) * 100
                elif "cpu2_total" in data:
                    cpu2_total = sanitize_string(data.split(':')[1])
                elif "cpu2_usage" in data:
                    cpu2_usage = sanitize_string(data.split(':')[1])
                    cpu2_percent = (float(cpu2_usage) / float(cpu2_total)) * 100
                elif "cpu3_total" in data:
                    cpu3_total = sanitize_string(data.split(':')[1])
                elif "cpu3_usage" in data:
                    cpu3_usage = sanitize_string(data.split(':')[1])
                    cpu3_percent = (float(cpu3_usage) / float(cpu3_total)) * 100
                elif "cpu4_total" in data:
                    cpu4_total = sanitize_string(data.split(':')[1])
                elif "cpu4_usage" in data:
                    cpu4_usage = sanitize_string(data.split(':')[1])
                    cpu4_percent = (float(cpu4_usage) / float(cpu4_total)) * 100



            except Exception as e:
                print(e)
                print('Something went wrong with the CPU metrics')
        cpu1_percent_metric.set(cpu1_percent if cpu1_percent is not None else float('nan'))
        cpu2_percent_metric.set(cpu2_percent if cpu2_percent is not None else float('nan'))
        cpu3_percent_metric.set(cpu3_percent if cpu3_percent is not None else float('nan'))
        cpu4_percent_metric.set(cpu4_percent if cpu4_percent is not None else float('nan'))

    if "memory_usage" in payload:
        memory_usage_list = payload.split(',')
        sanitized_format_memory = memory_usage_list
        for data in sanitized_format_memory:
            if "mem_total" in data:
                memory_total = data.split(':')[2].strip('"')
            elif "mem_free" in data:
                memory_free = data.split(':')[1].strip('"')
            elif "mem_used" in data:
                #We use strip to clean up the string return carriages and spaces
                memory_used = data.split(':')[1].replace('}', '').strip().strip('"')
        memory_total_metric.set(float(memory_total))
        memory_free_metric.set(float(memory_free))
        memory_used_metric.set(float(memory_used))

    elif "uptime" in payload:
        # 這個 hook 回的不是嚴格 JSON——"uptime" 的值是沒加引號的日期字串
        # (例如 `"uptime":Tue, 22 Sep 2026 17:35:15 +0800(2769597 secs
        # since boot)`),上游原本直接 json.loads(payload) 會直接
        # JSONDecodeError 炸掉,這是 ASUS 這批 hook 本來的設計問題(給
        # 網頁前端 eval() 當 JS 物件字面值用,不保證是合法 JSON,不同
        # 韌體版本引不引號都可能不一樣)。改成直接用 regex 從原始文字裡
        # 撈「(N secs since boot)」這段,不依賴整段是合法 JSON、也不管
        # 日期部分的格式。
        match = search(r'\((\d+)\s*secs? since boot\)', payload)
        if match:
            uptime_metric.set(float(match.group(1)))

    elif "get_clientlist" in payload:
        json_payload = json.loads(payload)
        #print(json_payload)
        for device in json_payload['get_clientlist']['maclist']:
            current_device = json_payload['get_clientlist'][device]
            # Device is wired only - no wireless statistics
            if current_device['isWL'] == '0':
                continue
            #print(current_device)
            if current_device['name'] == '':
                current_device['name'] = current_device['mac']
            active_device_metric.labels(ip_address=current_device['ip'],
                                        device_name=current_device['name'],
                                        connection_type='wireless',
                                        metric='Current RX speed Mb',
                                        mac_address=current_device['mac']).set(safe_float(current_device['curRx']))
            active_device_metric.labels(ip_address=current_device['ip'],
                                        device_name=current_device['name'],
                                        connection_type='wireless',
                                        metric='Current TX speed Mb',
                                        mac_address=current_device['mac']).set(safe_float(current_device['curTx']))
            active_device_metric.labels(ip_address=current_device['ip'],
                                        device_name=current_device['name'],
                                        connection_type='wireless',
                                        metric='RSSI',
                                        mac_address=current_device['mac']).set(safe_float(current_device['rssi']))

            try:
                total_connected_time = current_device['wlConnectTime'].split(':')
                total_connected_time_seconds = (int(total_connected_time[0]) * 3600) + (int(total_connected_time[1]) * 60) + int(total_connected_time[2])
            except (ValueError, IndexError):
                total_connected_time_seconds = float('nan')
            active_device_metric.labels(ip_address=current_device['ip'],
                                        device_name=current_device['name'],
                                        connection_type='wireless',
                                        metric='Time connected to wireless network',
                                        mac_address=current_device['mac']).set(float(total_connected_time_seconds))
    elif "wanlink" in payload:
        parse_wanlink_status(payload)

def login_router():
    router_username = getenv('ASUS_USERNAME')
    router_password = getenv('ASUS_PASSWORD')
    asus_ip = getenv('ASUS_IP')
    account = f"{router_username}:{router_password}"

    string_bytes = account.encode('ascii')
    base64_bytes = base64.b64encode(string_bytes)
    login = base64_bytes.decode('ascii')

    # ASUS_SCHEME/ASUS_PORT 是這次 vendor 進來時加的(見檔案開頭的差異
    # 說明),不是上游原本就有——WAN 端管理介面(「Enable Web Access from
    # WAN」)預設是 HTTPS + 8443,不是路由器 LAN 端那組預設的 HTTP:80。
    scheme = getenv('ASUS_SCHEME', 'https')
    port = getenv('ASUS_PORT', '8443')
    base_url = '{}://{}:{}'.format(scheme, asus_ip, port) if port else '{}://{}'.format(scheme, asus_ip)

    url = base_url + '/login.cgi'
    payload = "login_authorization=" + login
    headers = {
        'user-agent': "asusrouter-Android-DUTUtil-1.0.0.245"
    }
    # verify=False:WAN 端管理介面是自簽憑證(見檔案開頭說明);
    # timeout:上游原本完全沒設,連不到的話 requests 會卡到系統 TCP
    # 逾時(可能好幾分鐘)才會進到 main() 的 except,重試迴圈形同卡死,
    # 而且什麼 log 都看不到,這裡補上合理的逾時,壞掉要快點知道。
    r = requests.post(url=url, data=payload, headers=headers, verify=False, timeout=10)
    token = r.json()['asus_token']
    #print(token)

    #payload_list = ["uptime()", "memory_usage()", "cpu_usage()", "get_clientlist()", "netdev(appobj)", "wanlink()"]
    payload_list = ["uptime()", "memory_usage()", "cpu_usage()", "get_clientlist()", "wanlink()"]

    headers = {
    'user-Agent': "asusrouter-Android-DUTUtil-1.0.0.245",
    'cookie': 'asus_token={}'.format(token),
    }
    for payload in payload_list:
        formated_payload = "hook="+payload+';'
        try:
            r = requests.post(
                url=base_url + '/appGet.cgi',
                data=formated_payload,
                headers=headers,
                verify=False,
                timeout=10,
            )
            #print(r.text)
            parse_payload(r.text)
        except Exception as e:
            print(e)
            print('Failed')


def main():
    print("Starting Prometheus ASUS Router")
    health_check()
    start_http_server(8000)

    while True:
        try:
            login_router()
            sleep(5)
        except Exception as e:
            sleep(5)
            print('Failed to login to the router')

if __name__ == '__main__':
    main()
