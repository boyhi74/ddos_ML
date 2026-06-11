import time
import re
import subprocess
import os
from dash import Dash, dcc, html, Input, Output
import plotly.express as px
import pandas as pd
from collections import deque
import requests

# Đường dẫn tới file log
LOG_FILE = '/home/defense/ddos_defense/logs/defense.log'

# Thông tin Telegram
TELEGRAM_BOT_TOKEN = "x"
TELEGRAM_CHAT_ID = "x" 

# Dữ liệu cho dashboard
dashboard_data = {
    'time': deque(maxlen=50),
    'syn': deque(maxlen=50),
    'udp': deque(maxlen=50),
    'icmp': deque(maxlen=50),
    'http': deque(maxlen=50),
    'slowloris': deque(maxlen=50),
    'ldap': deque(maxlen=50),
    'mssql': deque(maxlen=50),
    'netbios': deque(maxlen=50),
    'portmap': deque(maxlen=50),
    'dns': deque(maxlen=50),
    'ntp': deque(maxlen=50)
}

# Xóa cổng 8050 nếu đang được sử dụng
def clear_port_8050():
    try:
        # Tìm tiến trình đang sử dụng cổng 8050
        result = subprocess.run("lsof -i :8050 | grep LISTEN | awk '{print $2}'", shell=True, capture_output=True, text=True)
        pid = result.stdout.strip()
        if pid:
            print(f"Tìm thấy tiến trình {pid} đang sử dụng cổng 8050. Đang dừng...")
            subprocess.run(f"kill -9 {pid}", shell=True, check=True)
            print("Cổng 8050 đã được giải phóng.")
        else:
            print("Cổng 8050 không được sử dụng.")
    except subprocess.CalledProcessError as e:
        print(f"Lỗi khi giải phóng cổng 8050: {e}")

# Đọc file log để lấy dữ liệu
def read_log_data():
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            attack_message = None
            packet_counts = {
                'syn': 0, 'udp': 0, 'icmp': 0, 'http': 0, 'slowloris': 0,
                'ldap': 0, 'mssql': 0, 'netbios': 0, 'portmap': 0, 'dns': 0, 'ntp': 0
            }
            # Tìm dòng cuối cùng chứa "Phát hiện tấn công"
            for line in reversed(lines):
                if "Phát hiện tấn công" in line and not attack_message:
                    attack_message = line.strip()
                    # Trích xuất số lượng gói tin từ dòng "Phát hiện tấn công"
                    if "UDP flood" in attack_message:
                        udp_match = re.search(r"UDP Packets: (\d+)", attack_message)
                        dns_match = re.search(r"DNS Packets: (\d+)", attack_message)
                        ntp_match = re.search(r"NTP Packets: (\d+)", attack_message)
                        if udp_match:
                            packet_counts['udp'] = int(udp_match.group(1))
                        if dns_match:
                            packet_counts['dns'] = int(dns_match.group(1))
                        if ntp_match:
                            packet_counts['ntp'] = int(ntp_match.group(1))
                    elif "LDAP amplification" in attack_message:
                        ldap_match = re.search(r"LDAP Packets: (\d+)", attack_message)
                        if ldap_match:
                            packet_counts['ldap'] = int(ldap_match.group(1))
                    elif "MSSQL amplification" in attack_message:
                        mssql_match = re.search(r"MSSQL Packets: (\d+)", attack_message)
                        if mssql_match:
                            packet_counts['mssql'] = int(mssql_match.group(1))
                    elif "NetBIOS amplification" in attack_message:
                        netbios_match = re.search(r"NetBIOS Packets: (\d+)", attack_message)
                        if netbios_match:
                            packet_counts['netbios'] = int(netbios_match.group(1))
                    elif "Portmap amplification" in attack_message:
                        portmap_match = re.search(r"Portmap Packets: (\d+)", attack_message)
                        if portmap_match:
                            packet_counts['portmap'] = int(portmap_match.group(1))
                    break
            return packet_counts, attack_message
    except Exception as e:
        print(f"Lỗi khi đọc log: {e}")
        return None, None

# Gửi cảnh báo Telegram
def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    try:
        response = requests.post(url, json=payload)
        if response.status_code != 200:
            print(f"Lỗi gửi Telegram: {response.text}")
    except Exception as e:
        print(f"Lỗi gửi Telegram: {e}")

# Cập nhật dữ liệu dashboard và kiểm tra tấn công
last_attack_message = None
def update_dashboard_data():
    global last_attack_message
    packet_counts, attack_message = read_log_data()
    print(f"Packet counts: {packet_counts}")
    print(f"Attack message: {attack_message}")
    if packet_counts:
        current_time = time.time()
        dashboard_data['time'].append(current_time)
        dashboard_data['syn'].append(packet_counts.get('syn', 0))
        dashboard_data['udp'].append(packet_counts.get('udp', 0))
        dashboard_data['icmp'].append(packet_counts.get('icmp', 0))
        dashboard_data['http'].append(packet_counts.get('http', 0))
        dashboard_data['slowloris'].append(packet_counts.get('slowloris', 0))
        dashboard_data['ldap'].append(packet_counts.get('ldap', 0))
        dashboard_data['mssql'].append(packet_counts.get('mssql', 0))
        dashboard_data['netbios'].append(packet_counts.get('netbios', 0))
        dashboard_data['portmap'].append(packet_counts.get('portmap', 0))
        dashboard_data['dns'].append(packet_counts.get('dns', 0))
        dashboard_data['ntp'].append(packet_counts.get('ntp', 0))
    
    if attack_message and attack_message != last_attack_message:
        send_telegram_alert(attack_message)
        last_attack_message = attack_message

# Khởi tạo Dash app
app = Dash(__name__)

app.layout = html.Div([
    html.H1("DDoS Monitor: Dashboard & Alerts"),
    dcc.Graph(id='live-graph'),
    dcc.Interval(id="interval-component", interval=5*1000, n_intervals=0)
])

@app.callback(
    Output('live-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_graph(n):
    update_dashboard_data()
    df = pd.DataFrame(dashboard_data)
    fig = px.line(df, x='time', y=['syn', 'udp', 'icmp', 'http', 'slowloris', 'ldap', 'mssql', 'netbios', 'portmap', 'dns', 'ntp'],
                  title='Real-Time Traffic Monitoring',
                  labels={'value': 'Packet Count', 'time': 'Time'})
    return fig

if __name__ == "__main__":
    # Giải phóng cổng 8050 trước khi chạy
    clear_port_8050()
    app.run(debug=False, host='0.0.0.0', port=8050)
