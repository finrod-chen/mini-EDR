# vendor 自 https://github.com/LaurentDumont/asus-router-exporter
# commit 8fd39180f21e2c0907a273ef8ad916d9e4fe0200(asus-exporter.py,原始檔名相同)。
# 上游 repo 沒有附 LICENSE 檔(預設保留著作權),這裡是個人/內部使用,
# 不對外散布。內容照原樣保留,不修改邏輯——只有這一段來源註記是新加的。
# 如果要更新版本,直接對照上游同一個檔案重新複製,沒有自動同步機制,
# 見 deploy/asus-exporter/README.md。

from time import sleep
import requests
import base64
from os import getenv
import json
from prometheus_client import start_http_server, Gauge
from re import sub, compile, findall


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

def parse_payload(payload):
    #print(payload)

    if "cpu_usage" in payload:
        sanitized_format_cpu = payload.split(',')

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
        cpu1_percent_metric.set(cpu1_percent)
        cpu2_percent_metric.set(cpu2_percent)
        cpu3_percent_metric.set(cpu3_percent)
        cpu4_percent_metric.set(cpu4_percent)

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
        json_payload = json.loads(payload)
        # Calculate uptime
        if json_payload['uptime']:
            uptime_seconds = json_payload['uptime'].split(' ')[5].split('(')[1]
            #print(uptime_seconds)
            uptime_metric.set(uptime_seconds)

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
                                        mac_address=current_device['mac']).set(float(current_device['curRx']))
            active_device_metric.labels(ip_address=current_device['ip'],
                                        device_name=current_device['name'],
                                        connection_type='wireless',
                                        metric='Current TX speed Mb',
                                        mac_address=current_device['mac']).set(float(current_device['curTx']))
            active_device_metric.labels(ip_address=current_device['ip'],
                                        device_name=current_device['name'],
                                        connection_type='wireless',
                                        metric='RSSI',
                                        mac_address=current_device['mac']).set(float(current_device['rssi']))

            total_connected_time = current_device['wlConnectTime'].split(':')
            total_connected_time_seconds = (int(total_connected_time[0]) * 3600) + (int(total_connected_time[1]) * 60) + int(total_connected_time[2])
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

    url = 'http://{}/login.cgi'.format(asus_ip)
    payload = "login_authorization=" + login
    headers = {
        'user-agent': "asusrouter-Android-DUTUtil-1.0.0.245"
    }
    r = requests.post(url=url, data=payload, headers=headers)
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
            r = requests.post(url='http://{}/appGet.cgi'.format(asus_ip), data=formated_payload, headers=headers)
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
