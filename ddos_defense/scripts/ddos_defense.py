import scapy.all as scapy
import pandas as pd
import numpy as np
import joblib
import subprocess
import logging
from collections import defaultdict, deque
import time
import os

# Thiết lập logging
logging.basicConfig(
    filename='/home/defense/ddos_defense/logs/defense.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Tải mô hình, scaler và label_encoder
MODEL_PATH = '/home/defense/ddos_defense/models/ddos_model.pkl'
SCALER_PATH = '/home/defense/ddos_defense/models/scaler.pkl'
LABEL_ENCODER_PATH = '/home/defense/ddos_defense/models/label_encoder.pkl'

try:
    scaler = joblib.load(SCALER_PATH)
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    logging.info("Đã tải mô hình, scaler và label_encoder thành công.")
except Exception as e:
    logging.error(f"Lỗi khi tải mô hình, scaler hoặc label_encoder: {e}")
    raise

# Biến lưu trữ dữ liệu tạm thời
traffic_data = defaultdict(list)

# Biến đếm số lượng gói theo loại
packet_counts = {
    'syn': 0,
    'udp': 0,
    'udp_lag': 0,
    'ldap': 0,
    'mssql': 0,
    'netbios': 0,
    'portmap': 0,
    'dns': 0,
    'ntp': 0,
    'icmp': 0,
    'http': 0,
    'slowloris': 0
}

# Lưu trữ lưu lượng trung bình để tính ngưỡng động
average_traffic = {
    'syn': deque(maxlen=5),
    'udp': deque(maxlen=5),
    'udp_lag': deque(maxlen=5),
    'ldap': deque(maxlen=5),
    'mssql': deque(maxlen=5),
    'netbios': deque(maxlen=5),
    'portmap': deque(maxlen=5),
    'dns': deque(maxlen=5),
    'ntp': deque(maxlen=5),
    'icmp': deque(maxlen=5),
    'http': deque(maxlen=5),
    'slowloris': deque(maxlen=5)
}

# Danh sách đen để lưu các IP đã chặn
blacklist = set()

# Lưu trữ các kết nối TCP đang mở để phát hiện Slowloris
open_connections = defaultdict(list)

def packet_callback(packet):
    """Xử lý từng gói tin"""
    global packet_counts
    
    current_time = time.time()
    
    if not packet.haslayer(scapy.IP):
        return
    
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    packet_size = len(packet)
    protocol = packet[scapy.IP].proto
    
    src_port = 0
    dst_port = 0
    tcp_flags = 0
    window = 0
    
    # Phát hiện gói SYN (TCP)
    if packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
        tcp_flags = packet[scapy.TCP].flags
        window = packet[scapy.TCP].window
        
        if tcp_flags & 0x02:  # SYN flag
            packet_counts['syn'] += 1
            # Theo dõi kết nối Slowloris trên cổng 80/443
            if dst_port in [80, 443]:
                open_connections[src_ip].append((current_time, False))  # (thời gian, trạng thái ACK)
        
        # Kiểm tra gói HTTP/HTTPS
        if dst_port in [80, 443]:
            packet_counts['http'] += 1
        
        # Kiểm tra kết nối Slowloris: Nếu có ACK, đánh dấu kết nối đã hoàn tất
        if tcp_flags & 0x10:  # ACK flag
            for conn in open_connections[src_ip]:
                if not conn[1]:  # Nếu chưa có ACK
                    open_connections[src_ip].remove(conn)
                    open_connections[src_ip].append((conn[0], True))
                    break
    
    # Phát hiện gói UDP
    if packet.haslayer(scapy.UDP):
        packet_counts['udp'] += 1
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
        
        if packet_size > 1000:
            packet_counts['udp_lag'] += 1
        
        if dst_port == 389:
            packet_counts['ldap'] += 1
        if dst_port == 1433:
            packet_counts['mssql'] += 1
        if dst_port == 137:
            packet_counts['netbios'] += 1
        if dst_port == 111:
            packet_counts['portmap'] += 1
        if dst_port == 53:
            packet_counts['dns'] += 1
        if dst_port == 123:
            packet_counts['ntp'] += 1
    
    # Phát hiện gói ICMP
    if protocol == 1:  # ICMP
        packet_counts['icmp'] += 1
    
    # Lưu dữ liệu gói tin
    if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) or protocol == 1:
        traffic_data['timestamp'].append(current_time)
        traffic_data['src_ip'].append(src_ip)
        traffic_data['dst_ip'].append(dst_ip)
        traffic_data['packet_size'].append(packet_size)
        traffic_data['protocol'].append(protocol)
        traffic_data['src_port'].append(src_port)
        traffic_data['dst_port'].append(dst_port)
        traffic_data['tcp_flags'].append(tcp_flags)
        traffic_data['window'].append(window)

def capture_traffic(interface="ens33", duration=10):
    """Thu thập lưu lượng mạng"""
    global packet_counts
    packet_counts = {
        'syn': 0, 'udp': 0, 'udp_lag': 0, 'ldap': 0, 'mssql': 0, 'netbios': 0,
        'portmap': 0, 'dns': 0, 'ntp': 0, 'icmp': 0, 'http': 0, 'slowloris': 0
    }
    
    logging.info(f"Bắt đầu thu thập lưu lượng trên {interface} trong {duration} giây...")
    print(f"Bắt đầu thu thập lưu lượng trên {interface} trong {duration} giây...")
    # Tạo bộ lọc để bỏ qua các IP trong blacklist và chỉ thu thập TCP, UDP, ICMP
    filter_str = "tcp or udp or icmp"
    if blacklist:
        blacklist_filter = " and ".join([f"not src host {ip}" for ip in blacklist])
        filter_str = f"({filter_str}) and ({blacklist_filter})"
    packets = scapy.sniff(iface=interface, prn=packet_callback, filter=filter_str, timeout=duration)
    df = pd.DataFrame(traffic_data)
    print(f"Số gói tin thu thập được: {len(df)}")
    if len(packets) > 0:
        print(f"Gói tin mẫu: {packets[0].summary()}")
    return df

def extract_features(df):
    """Trích xuất đặc trưng từ dữ liệu thô"""
    if df.empty:
        logging.warning("Không có dữ liệu để xử lý.")
        return None, None, None
    
    features = {}
    
    expected_features = [
        'Unnamed: 0', 'Source Port', 'Destination Port', 'Protocol', 'Flow Duration',
        'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min',
        'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max',
        'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
        'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
        'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
        'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
        'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
        'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
        'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
        'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
        'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
        'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
        'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
        'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
        'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
        'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
        'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
        'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Inbound', 'Label'
    ]
    
    features['Unnamed: 0'] = 0
    features['Source Port'] = df['src_port'].mean() if not df['src_port'].empty else 0
    features['Destination Port'] = df['dst_port'].mean() if not df['dst_port'].empty else 0
    features['Protocol'] = df['protocol'].mode()[0] if not df['protocol'].empty else 0
    
    if len(df['timestamp']) > 1:
        features['Flow Duration'] = (df['timestamp'].max() - df['timestamp'].min()) * 1e6
    else:
        features['Flow Duration'] = 0
    
    features['Total Fwd Packets'] = len(df)
    features['Total Backward Packets'] = 0
    
    features['Total Length of Fwd Packets'] = df['packet_size'].sum()
    features['Total Length of Bwd Packets'] = 0
    features['Fwd Packet Length Max'] = df['packet_size'].max() if not df['packet_size'].empty else 0
    features['Fwd Packet Length Min'] = df['packet_size'].min() if not df['packet_size'].empty else 0
    features['Fwd Packet Length Mean'] = df['packet_size'].mean() if not df['packet_size'].empty else 0
    features['Fwd Packet Length Std'] = df['packet_size'].std() if not df['packet_size'].empty else 0
    features['Bwd Packet Length Max'] = 0
    features['Bwd Packet Length Min'] = 0
    features['Bwd Packet Length Mean'] = 0
    features['Bwd Packet Length Std'] = 0
    
    if features['Flow Duration'] > 0:
        features['Flow Bytes/s'] = (features['Total Length of Fwd Packets'] / features['Flow Duration']) * 1e6
        features['Flow Packets/s'] = (len(df) / features['Flow Duration']) * 1e6
    else:
        features['Flow Bytes/s'] = 0
        features['Flow Packets/s'] = 0
    
    if len(df['timestamp']) > 1:
        iat = df['timestamp'].diff().dropna()
        features['Flow IAT Mean'] = iat.mean() * 1e6
        features['Flow IAT Std'] = iat.std() * 1e6
        features['Flow IAT Max'] = iat.max() * 1e6
        features['Flow IAT Min'] = iat.min() * 1e6
        features['Fwd IAT Total'] = features['Flow Duration']
        features['Fwd IAT Mean'] = features['Flow IAT Mean']
        features['Fwd IAT Std'] = features['Flow IAT Std']
        features['Fwd IAT Max'] = features['Flow IAT Max']
        features['Fwd IAT Min'] = features['Flow IAT Min']
    else:
        features['Flow IAT Mean'] = 0
        features['Flow IAT Std'] = 0
        features['Flow IAT Max'] = 0
        features['Flow IAT Min'] = 0
        features['Fwd IAT Total'] = 0
        features['Fwd IAT Mean'] = 0
        features['Fwd IAT Std'] = 0
        features['Fwd IAT Max'] = 0
        features['Fwd IAT Min'] = 0
    
    features['Bwd IAT Total'] = 0
    features['Bwd IAT Mean'] = 0
    features['Bwd IAT Std'] = 0
    features['Bwd IAT Max'] = 0
    features['Bwd IAT Min'] = 0
    
    fin_count = syn_count = rst_count = psh_count = ack_count = urg_count = cwe_count = ece_count = 0
    for flags in df['tcp_flags']:
        if flags is not None:
            if flags & 0x01:  # FIN
                fin_count += 1
            if flags & 0x02:  # SYN
                syn_count += 1
            if flags & 0x04:  # RST
                rst_count += 1
            if flags & 0x08:  # PSH
                psh_count += 1
            if flags & 0x10:  # ACK
                ack_count += 1
            if flags & 0x20:  # URG
                urg_count += 1
            if flags & 0x40:  # ECE
                ece_count += 1
            if flags & 0x80:  # CWE
                cwe_count += 1
    
    features['Fwd PSH Flags'] = psh_count
    features['Bwd PSH Flags'] = 0
    features['Fwd URG Flags'] = urg_count
    features['Bwd URG Flags'] = 0
    features['FIN Flag Count'] = fin_count
    features['SYN Flag Count'] = syn_count
    features['RST Flag Count'] = rst_count
    features['PSH Flag Count'] = psh_count
    features['ACK Flag Count'] = ack_count
    features['URG Flag Count'] = urg_count
    features['CWE Flag Count'] = cwe_count
    features['ECE Flag Count'] = ece_count
    
    features['Fwd Header Length'] = 40 * len(df)
    features['Bwd Header Length'] = 0
    features['Fwd Header Length.1'] = features['Fwd Header Length']
    
    features['Fwd Packets/s'] = features['Flow Packets/s']
    features['Bwd Packets/s'] = 0
    
    features['Min Packet Length'] = features['Fwd Packet Length Min']
    features['Max Packet Length'] = features['Fwd Packet Length Max']
    features['Packet Length Mean'] = features['Fwd Packet Length Mean']
    features['Packet Length Std'] = features['Fwd Packet Length Std']
    features['Packet Length Variance'] = features['Packet Length Std'] ** 2 if features['Packet Length Std'] > 0 else 0
    
    features['Down/Up Ratio'] = 0
    features['Average Packet Size'] = features['Packet Length Mean']
    features['Avg Fwd Segment Size'] = features['Fwd Packet Length Mean']
    features['Avg Bwd Segment Size'] = 0
    
    features['Fwd Avg Bytes/Bulk'] = 0
    features['Fwd Avg Packets/Bulk'] = 0
    features['Fwd Avg Bulk Rate'] = 0
    features['Bwd Avg Bytes/Bulk'] = 0
    features['Bwd Avg Packets/Bulk'] = 0
    features['Bwd Avg Bulk Rate'] = 0
    
    features['Subflow Fwd Packets'] = features['Total Fwd Packets']
    features['Subflow Fwd Bytes'] = features['Total Length of Fwd Packets']
    features['Subflow Bwd Packets'] = 0
    features['Subflow Bwd Bytes'] = 0
    
    features['Init_Win_bytes_forward'] = df['window'].max() if not df['window'].empty else 0
    features['Init_Win_bytes_backward'] = 0
    
    features['act_data_pkt_fwd'] = len(df[df['packet_size'] > 40])
    features['min_seg_size_forward'] = 20
    
    features['Active Mean'] = features['Flow Duration'] / 2
    features['Active Std'] = 0
    features['Active Max'] = features['Flow Duration']
    features['Active Min'] = 0
    features['Idle Mean'] = 0
    features['Idle Std'] = 0
    features['Idle Max'] = 0
    features['Idle Min'] = 0
    
    features['Inbound'] = 1
    
    features['Label'] = 0
    
    features_df = pd.DataFrame([features])[expected_features]
    
    print(f"SYN Flag Count: {features['SYN Flag Count']}")
    print(f"Flow Packets/s: {features['Flow Packets/s']}")
    print(f"Total Fwd Packets: {features['Total Fwd Packets']}")
    print(f"Flow Duration (microseconds): {features['Flow Duration']}")
    print(f"UDP Packets: {packet_counts['udp']}")
    print(f"DNS Packets: {packet_counts['dns']}")
    print(f"NTP Packets: {packet_counts['ntp']}")
    print(f"UDPLag Packets: {packet_counts['udp_lag']}")
    print(f"LDAP Packets: {packet_counts['ldap']}")
    print(f"MSSQL Packets: {packet_counts['mssql']}")
    print(f"NetBIOS Packets: {packet_counts['netbios']}")
    print(f"Portmap Packets: {packet_counts['portmap']}")
    print(f"ICMP Packets: {packet_counts['icmp']}")
    print(f"HTTP Packets: {packet_counts['http']}")
    print(f"Slowloris Connections: {packet_counts['slowloris']}")
    
    # Tính kích thước gói trung bình
    avg_packet_size = df['packet_size'].mean() if not df['packet_size'].empty else 0
    print(f"Average Packet Size: {avg_packet_size:.2f} bytes")
    
    # Xác định suspect_ip dựa trên IP có số lượng gói lớn nhất
    suspect_ip = df['src_ip'].mode()[0] if not df['src_ip'].empty else "0.0.0.0"
    
    return features_df, suspect_ip, avg_packet_size

def preprocess_data(features_df):
    """Chuẩn hóa dữ liệu"""
    try:
        print("Đang chuẩn hóa dữ liệu...")
        print(f"Số cột trong features_df: {len(features_df.columns)}")
        print(f"Các cột trong features_df: {list(features_df.columns)}")
        features_scaled = scaler.transform(features_df)
        print("Chuẩn hóa thành công.")
        return features_scaled
    except Exception as e:
        logging.error(f"Lỗi khi chuẩn hóa dữ liệu: {e}")
        print(f"Lỗi khi chuẩn hóa dữ liệu: {e}")
        return None

def predict(features_scaled):
    """Dự đoán bằng mô hình"""
    try:
        print("Đang dự đoán...")
        prediction = model.predict(features_scaled)
        prediction = prediction.astype(np.int64)
        print(f"Dự đoán: {prediction}")
        return prediction
    except Exception as e:
        logging.error(f"Lỗi khi dự đoán: {e}")
        print(f"Lỗi khi dự đoán: {e}")
        return None

def block_ip(ip):
    """Chặn IP bằng iptables hoặc nftables"""
    if ip == "0.0.0.0":
        logging.warning("Không thể chặn IP 0.0.0.0 (IP không hợp lệ).")
        print("Không thể chặn IP 0.0.0.0 (IP không hợp lệ).")
        return False
    
    # Thêm IP vào blacklist
    blacklist.add(ip)
    
    try:
        # Đảm bảo chain INPUT và FORWARD tồn tại
        subprocess.run("sudo iptables -N DDOS_INPUT || true", shell=True, check=False)
        subprocess.run("sudo iptables -N DDOS_FORWARD || true", shell=True, check=False)
        subprocess.run("sudo iptables -A INPUT -j DDOS_INPUT", shell=True, check=False)
        subprocess.run("sudo iptables -A FORWARD -j DDOS_FORWARD", shell=True, check=False)
        
        # Kiểm tra xem IP đã bị chặn chưa
        cmd_check_iptables = f"sudo iptables -C DDOS_INPUT -s {ip} -j DROP"
        result_iptables = subprocess.run(cmd_check_iptables, shell=True, capture_output=True, text=True)
        if result_iptables.returncode == 0:
            logging.info(f"IP {ip} đã được chặn trước đó (iptables).")
            print(f"IP {ip} đã được chặn trước đó (iptables).")
            return True
        
        cmd_check_nftables = f"sudo nft list ruleset | grep 'ip saddr {ip} drop'"
        result_nftables = subprocess.run(cmd_check_nftables, shell=True, capture_output=True, text=True)
        if "ip saddr" in result_nftables.stdout:
            logging.info(f"IP {ip} đã được chặn trước đó (nftables).")
            print(f"IP {ip} đã được chặn trước đó (nftables).")
            return True
    except subprocess.CalledProcessError as e:
        logging.warning(f"Lỗi khi kiểm tra trạng thái chặn IP {ip}: {e}")
        print(f"Lỗi khi kiểm tra trạng thái chặn IP {ip}: {e}")

    try:
        # Xóa quy tắc cũ nếu có
        cmd_remove_iptables_input = f"sudo iptables -D DDOS_INPUT -s {ip} -j DROP 2>/dev/null || true"
        cmd_remove_iptables_forward = f"sudo iptables -D DDOS_FORWARD -s {ip} -j DROP 2>/dev/null || true"
        subprocess.run(cmd_remove_iptables_input, shell=True, check=False)
        subprocess.run(cmd_remove_iptables_forward, shell=True, check=False)
        
        # Thêm quy tắc mới vào cả INPUT và FORWARD, chèn vào đầu chain
        cmd_add_iptables_input = f"sudo iptables -I DDOS_INPUT 1 -s {ip} -j DROP"
        cmd_add_iptables_forward = f"sudo iptables -I DDOS_FORWARD 1 -s {ip} -j DROP"
        subprocess.run(cmd_add_iptables_input, shell=True, check=True)
        subprocess.run(cmd_add_iptables_forward, shell=True, check=True)
        
        # Kiểm tra xem quy tắc đã được thêm thành công chưa
        cmd_verify_iptables = f"sudo iptables -C DDOS_INPUT -s {ip} -j DROP"
        result_verify = subprocess.run(cmd_verify_iptables, shell=True, capture_output=True, text=True)
        if result_verify.returncode != 0:
            raise subprocess.CalledProcessError(result_verify.returncode, cmd_verify_iptables, result_verify.stderr)
        
        logging.info(f"Đã chặn IP: {ip} (iptables)")
        print(f"Đã chặn IP: {ip} (iptables)")
        subprocess.run("sudo mkdir -p /etc/iptables", shell=True-True)
        subprocess.run("sudo iptables-save > /etc/iptables/rules.v4", shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.warning(f"Không thể chặn IP {ip} bằng iptables, thử nftables: {e}")
        print(f"Không thể chặn IP {ip} bằng iptables, thử nftables: {e}")

    try:
        cmd_remove_nftables = f"sudo nft delete rule ip filter INPUT ip saddr {ip} drop 2>/dev/null || true"
        subprocess.run(cmd_remove_nftables, shell=True, check=False)
        
        cmd_add_nftables = f"sudo nft add rule ip filter INPUT ip saddr {ip} drop"
        subprocess.run(cmd_add_nftables, shell=True, check=True)
        logging.info(f"Đã chặn IP: {ip} (nftables)")
        print(f"Đã chặn IP: {ip} (nftables)")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Lỗi khi chặn IP {ip} bằng nftables: {e}")
        print(f"Lỗi khi chặn IP {ip} bằng nftables: {e}")
        return False

def main():
    interface = "ens33"
    if not os.path.exists('/sys/class/net/' + interface):
        logging.error(f"Giao diện {interface} không tồn tại.")
        print(f"Lỗi: Giao diện {interface} không tồn tại.")
        return
    
    logging.info("Hệ thống phòng chống DDoS khởi động.")
    print("Hệ thống phòng chống DDoS khởi động.")
    
    while True:
        traffic_data.clear()
        open_connections.clear()
        traffic_df = capture_traffic(interface=interface, duration=10)
        
        for key in packet_counts:
            average_traffic[key].append(packet_counts[key])
        
        thresholds = {}
        for key in average_traffic:
            avg = np.mean(average_traffic[key]) if average_traffic[key] else 0
            if key == 'syn':
                thresholds[key] = min(500, max(20, avg * 2))
            elif key == 'icmp':
                thresholds[key] = min(500, max(50, avg * 2))
            elif key == 'http':
                thresholds[key] = min(500, max(50, avg * 2))
            elif key == 'slowloris':
                thresholds[key] = min(50, max(5, avg * 2))
            elif key in ['mssql', 'netbios', 'portmap', 'ldap']:
                thresholds[key] = min(500, max(50, avg * 1.5))
            else:
                thresholds[key] = min(1000, max(100, avg * 2))
        
        print(f"Ngưỡng hiện tại: {thresholds}")
        
        if traffic_df is not None and not traffic_df.empty:
            features_df, suspect_ip, avg_packet_size = extract_features(traffic_df)
            
            if features_df is not None:
                syn_flag_count = features_df['SYN Flag Count'].iloc[0]
                flow_packets_s = features_df['Flow Packets/s'].iloc[0]
                total_packets = features_df['Total Fwd Packets'].iloc[0]
                
                # SYN Flood: Kiểm tra số lượng gói SYN và tỷ lệ gói SYN
                if total_packets > 0:
                    syn_ratio = syn_flag_count / total_packets
                    if (syn_flag_count > thresholds['syn'] and flow_packets_s > 200) or (syn_ratio > 0.8 and syn_flag_count > 5):
                        logging.warning(f"Phát hiện tấn công SYN flood từ IP: {suspect_ip} (SYN Flag Count: {syn_flag_count}, Flow Packets/s: {flow_packets_s}, SYN Ratio: {syn_ratio:.2f})")
                        print(f"Phát hiện tấn công SYN flood từ IP: {suspect_ip} (SYN Flag Count: {syn_flag_count}, Flow Packets/s: {flow_packets_s}, SYN Ratio: {syn_ratio:.2f})")
                        block_ip(suspect_ip)
                        continue
                
                # LDAP Amplification
                ldap_packets = packet_counts['ldap']
                if ldap_packets > thresholds['ldap']:
                    logging.warning(f"Phát hiện tấn công LDAP amplification từ IP: {suspect_ip} (LDAP Packets: {ldap_packets}, Avg Packet Size: {avg_packet_size:.2f})")
                    print(f"Phát hiện tấn công LDAP amplification từ IP: {suspect_ip} (LDAP Packets: {ldap_packets}, Avg Packet Size: {avg_packet_size:.2f})")
                    block_ip(suspect_ip)
                    continue
                
                # MSSQL Amplification
                mssql_packets = packet_counts['mssql']
                if mssql_packets > thresholds['mssql']:
                    logging.warning(f"Phát hiện tấn công MSSQL amplification từ IP: {suspect_ip} (MSSQL Packets: {mssql_packets}, Avg Packet Size: {avg_packet_size:.2f})")
                    print(f"Phát hiện tấn công MSSQL amplification từ IP: {suspect_ip} (MSSQL Packets: {mssql_packets}, Avg Packet Size: {avg_packet_size:.2f})")
                    block_ip(suspect_ip)
                    continue
                
                # NetBIOS Amplification
                netbios_packets = packet_counts['netbios']
                if netbios_packets > thresholds['netbios']:
                    logging.warning(f"Phát hiện tấn công NetBIOS amplification từ IP: {suspect_ip} (NetBIOS Packets: {netbios_packets}, Avg Packet Size: {avg_packet_size:.2f})")
                    print(f"Phát hiện tấn công NetBIOS amplification từ IP: {suspect_ip} (NetBIOS Packets: {netbios_packets}, Avg Packet Size: {avg_packet_size:.2f})")
                    block_ip(suspect_ip)
                    continue
                
                # Portmap Amplification
                portmap_packets = packet_counts['portmap']
                if portmap_packets > thresholds['portmap']:
                    logging.warning(f"Phát hiện tấn công Portmap amplification từ IP: {suspect_ip} (Portmap Packets: {portmap_packets}, Avg Packet Size: {avg_packet_size:.2f})")
                    print(f"Phát hiện tấn công Portmap amplification từ IP: {suspect_ip} (Portmap Packets: {portmap_packets}, Avg Packet Size: {avg_packet_size:.2f})")
                    block_ip(suspect_ip)
                    continue
                
                # UDP Flood: Chỉ kiểm tra nếu không phải là tấn công amplification
                udp_packets = packet_counts['udp']
                dns_packets = packet_counts['dns']
                ntp_packets = packet_counts['ntp']
                
                # Xác định suspect_ip dựa trên gói UDP
                udp_ip_counts = traffic_df[traffic_df['protocol'] == 17]['src_ip'].value_counts()
                if not udp_ip_counts.empty:
                    suspect_ip = udp_ip_counts.index[0]  # IP có số lượng gói UDP lớn nhất
                else:
                    suspect_ip = traffic_df['src_ip'].mode()[0] if not traffic_df['src_ip'].empty else "0.0.0.0"
                
                if udp_packets > 0:
                    dns_ratio = dns_packets / udp_packets
                    ntp_ratio = ntp_packets / udp_packets
                    # Chỉ phát hiện UDP Flood nếu không có dấu hiệu của các cuộc tấn công amplification
                    if (udp_packets > thresholds['udp']) and (ldap_packets <= thresholds['ldap']) and (mssql_packets <= thresholds['mssql']) and (netbios_packets <= thresholds['netbios']) and (portmap_packets <= thresholds['portmap']) and (dns_ratio <= 0.5) and (ntp_ratio <= 0.5):
                        logging.warning(f"Phát hiện tấn công UDP flood từ IP: {suspect_ip} (UDP Packets: {udp_packets}, DNS Packets: {dns_packets}, DNS Ratio: {dns_ratio:.2f}, NTP Packets: {ntp_packets}, NTP Ratio: {ntp_ratio:.2f})")
                        print(f"Phát hiện tấn công UDP flood từ IP: {suspect_ip} (UDP Packets: {udp_packets}, DNS Packets: {dns_packets}, DNS Ratio: {dns_ratio:.2f}, NTP Packets: {ntp_packets}, NTP Ratio: {ntp_ratio:.2f})")
                        block_ip(suspect_ip)
                        continue
                
                # UDPLag
                udp_lag_packets = packet_counts['udp_lag']
                if udp_lag_packets > thresholds['udp_lag']:
                    logging.warning(f"Phát hiện tấn công UDPLag từ IP: {suspect_ip} (UDPLag Packets: {udp_lag_packets}, Avg Packet Size: {avg_packet_size:.2f})")
                    print(f"Phát hiện tấn công UDPLag từ IP: {suspect_ip} (UDPLag Packets: {udp_lag_packets}, Avg Packet Size: {avg_packet_size:.2f})")
                    block_ip(suspect_ip)
                    continue
                
                # ICMP Flood
                icmp_packets = packet_counts['icmp']
                if icmp_packets > thresholds['icmp']:
                    logging.warning(f"Phát hiện tấn công ICMP flood từ IP: {suspect_ip} (ICMP Packets: {icmp_packets})")
                    print(f"Phát hiện tấn công ICMP flood từ IP: {suspect_ip} (ICMP Packets: {icmp_packets})")
                    block_ip(suspect_ip)
                    continue
                
                # HTTP Flood
                http_packets = packet_counts['http']
                if http_packets > thresholds['http']:
                    logging.warning(f"Phát hiện tấn công HTTP flood từ IP: {suspect_ip} (HTTP Packets: {http_packets})")
                    print(f"Phát hiện tấn công HTTP flood từ IP: {suspect_ip} (HTTP Packets: {http_packets})")
                    block_ip(suspect_ip)
                    continue
                
                # Slowloris
                current_time = time.time()
                for src_ip, conns in open_connections.items():
                    incomplete_conns = sum(1 for conn in conns if not conn[1] and (current_time - conn[0]) < 60)
                    if incomplete_conns > thresholds['slowloris']:
                        packet_counts['slowloris'] = incomplete_conns
                        logging.warning(f"Phát hiện tấn công Slowloris từ IP: {src_ip} (Incomplete Connections: {incomplete_conns})")
                        print(f"Phát hiện tấn công Slowloris từ IP: {src_ip} (Incomplete Connections: {incomplete_conns})")
                        block_ip(src_ip)
                        continue
                
                # Sử dụng mô hình học máy để dự đoán
                features_scaled = preprocess_data(features_df)
                if features_scaled is not None:
                    prediction = predict(features_scaled)
                    if prediction is not None:
                        prediction = prediction.astype(np.int64)
                        if prediction[0] != 0:
                            attack_type = label_encoder.inverse_transform(prediction)[0]
                            logging.warning(f"Phát hiện tấn công DDoS từ IP: {suspect_ip} (Loại: {attack_type})")
                            print(f"Phát hiện tấn công DDoS từ IP: {suspect_ip} (Loại: {attack_type})")
                            block_ip(suspect_ip)
                        else:
                            logging.info("Lưu lượng bình thường.")
                            print("Lưu lượng bình thường.")
                    else:
                        print("Không thể dự đoán.")
                else:
                    print("Không thể chuẩn hóa dữ liệu.")
            else:
                print("Không có dữ liệu để xử lý.")
        
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Hệ thống phòng chống DDoS dừng bởi người dùng.")
        print("Hệ thống phòng chống DDoS dừng bởi người dùng.")
    except Exception as e:
        logging.error(f"Lỗi hệ thống: {e}")
        print(f"Lỗi hệ thống: {e}")
